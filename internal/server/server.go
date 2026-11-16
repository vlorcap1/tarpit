// Package server exposes Telaraña over HTTP.
//
// Public listener (reached through the site's reverse proxy):
//
//	GET  /robots.txt       the site's robots.txt plus this visitor's trap paths
//	ANY  <prefix>/...      trap area: decoy page on the first hit, 404 after
//	ANY  /check            forward-auth endpoint: verdict headers (+ status)
//	GET  /healthz          liveness
//
// Admin listener (keep it private):
//
//	GET  /metrics          Prometheus metrics
//	GET  /healthz          liveness
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/vlorcap1/telarana/internal/clientip"
	"github.com/vlorcap1/telarana/internal/config"
	"github.com/vlorcap1/telarana/internal/goodbot"
	"github.com/vlorcap1/telarana/internal/metrics"
	"github.com/vlorcap1/telarana/internal/store"
	"github.com/vlorcap1/telarana/internal/trap"
	"github.com/vlorcap1/telarana/internal/verdict"
)

// Response headers set on /check, for the proxy to copy or route on.
const (
	HeaderVerdict = "X-Telarana-Verdict"
	HeaderScore   = "X-Telarana-Score"
	HeaderReasons = "X-Telarana-Reasons"
)

// Server holds Telaraña's HTTP handlers and their dependencies.
type Server struct {
	cfg        *config.Config
	traps      *trap.Traps
	store      store.Store
	bots       *goodbot.Verifier
	log        *slog.Logger
	robotsBase string
	now        func() time.Time

	Registry      *metrics.Registry
	mChecks       *metrics.CounterVec
	mTrapHits     *metrics.CounterVec
	mTrapped      *metrics.CounterVec
	mRobots       *metrics.CounterVec
	mBotChecks    *metrics.CounterVec
	mEnforcements *metrics.CounterVec
}

// Options are optional dependencies (zero values get production defaults).
type Options struct {
	Store      store.Store
	Resolver   goodbot.Resolver
	RobotsBase string
	Now        func() time.Time
}

// New wires a Server.
func New(cfg *config.Config, log *slog.Logger, opt Options) *Server {
	s := &Server{
		cfg:        cfg,
		traps:      trap.New(cfg.TrapPrefix, cfg.Secret, cfg.PreviousSecret),
		store:      opt.Store,
		log:        log,
		robotsBase: opt.RobotsBase,
		now:        opt.Now,
		Registry:   &metrics.Registry{},
	}
	if s.store == nil {
		s.store = store.NewMemory(cfg.MaxVisitors)
	}
	if s.now == nil {
		s.now = time.Now
	}
	r := s.Registry
	s.mChecks = r.Counter("telarana_checks_total", "Forward-auth checks by verdict.", "verdict",
		string(verdict.Clean), string(verdict.VerifiedBot), string(verdict.Suspect), string(verdict.Trapped))
	s.mTrapHits = r.Counter("telarana_trap_hits_total", "Requests to trap paths by kind.", "kind", "own", "shared")
	s.mTrapped = r.Counter("telarana_trapped_total", "Visitors confirmed as trapped, by cause.", "cause", "repeat", "shared")
	s.mRobots = r.Counter("telarana_robots_served_total", "robots.txt responses served.", "status", "ok")
	s.mBotChecks = r.Counter("telarana_goodbot_verifications_total", "Completed crawler verifications by result.", "result",
		goodbot.Verified.String(), goodbot.Impostor.String(), goodbot.Pending.String())
	s.mEnforcements = r.Counter("telarana_enforcements_total", "Checks answered with the enforce status.", "verdict", string(verdict.Trapped))
	r.Gauge("telarana_visitors_tracked", "Visitors currently held in memory.", func() float64 { return float64(s.store.Len()) })

	s.bots = goodbot.New(cfg.GoodBots, opt.Resolver, cfg.DNSTimeout, func(bot string, st goodbot.Status) {
		s.mBotChecks.Inc(st.String())
		lvl := slog.LevelInfo
		if st == goodbot.Impostor {
			lvl = slog.LevelWarn
		}
		s.log.Log(context.Background(), lvl, "crawler verification", "bot", bot, "result", st.String())
	})
	return s
}

// Bots exposes the crawler verifier (for waiting on it in tests/shutdown).
func (s *Server) Bots() *goodbot.Verifier { return s.bots }

// Store exposes the state backend (for the janitor).
func (s *Server) Store() store.Store { return s.store }

// PublicHandler serves robots.txt, the trap area and /check.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /robots.txt", s.handleRobots)
	mux.HandleFunc(s.traps.Prefix()+"/", s.handleTrap)
	mux.HandleFunc(s.traps.Prefix(), s.handleTrap)
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("GET /healthz", handleHealth)
	return mux
}

// AdminHandler serves /metrics and /healthz.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = s.Registry.WriteTo(w)
	})
	mux.HandleFunc("GET /healthz", handleHealth)
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

type who struct {
	ip      netip.Addr
	addrKey string // address (IPv6: /64), for traps and rate
	visitor string // address + User-Agent, for visitor state
	ua      string
}

func (s *Server) identify(r *http.Request) who {
	ip := clientip.FromRequest(r, s.cfg.TrustedProxies)
	addrKey := clientip.Key(ip)
	ua := r.UserAgent()
	sum := sha256.Sum256([]byte(ua))
	return who{ip: ip, addrKey: addrKey, visitor: addrKey + "|" + hex.EncodeToString(sum[:6]), ua: ua}
}

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	id := s.identify(r)
	s.store.Hit(id.addrKey, s.now(), s.cfg.RateWindow)

	var b strings.Builder
	if s.robotsBase != "" {
		b.WriteString(s.robotsBase)
		if !strings.HasSuffix(s.robotsBase, "\n") {
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	// RFC 9309: groups for the same user-agent are merged, so this group
	// adds to whatever the site's own robots.txt already says. The whole trap
	// area is disallowed, so compliant crawlers never enter it, not even
	// through the optional hidden link trap; the per-visitor paths are bait
	// for crawlers that mine robots.txt for interesting places.
	b.WriteString("User-agent: *\n")
	b.WriteString("Disallow: " + s.traps.Prefix() + "/\n")
	for _, p := range s.traps.Paths(id.addrKey) {
		b.WriteString("Disallow: " + p + "\n")
	}

	// The content differs per visitor: it must never be cached by a shared
	// cache, or visitors would receive each other's trap paths.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write([]byte(b.String()))
	s.mRobots.Inc("ok")
}

func (s *Server) handleTrap(w http.ResponseWriter, r *http.Request) {
	id := s.identify(r)
	s.store.Hit(id.addrKey, s.now(), s.cfg.RateWindow)
	kind := s.traps.Classify(id.addrKey, r.URL.Path)
	v := s.recordTrap(id, kind, r.URL.Path)

	w.Header().Set("Cache-Control", "private, no-store")
	if v.Trapped {
		http.NotFound(w, r)
		return
	}
	// First hit: a believable decoy that leads to a second trap. A curious
	// human who typed a path from robots.txt stops here; a crawler that
	// follows every link confirms itself.
	next := s.nextTrap(id.addrKey, r.URL.Path)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, decoyHTML, html.EscapeString(next))
}

const decoyHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">
<title>Internal tools</title></head>
<body><h1>Internal tools</h1><p>Restricted area. Available resources:</p>
<ul><li><a href="%s">Full database export</a></li></ul></body></html>
`

func (s *Server) nextTrap(addrKey, current string) string {
	paths := s.traps.Paths(addrKey)
	cur := path.Clean(current)
	for _, p := range paths {
		if p != cur {
			return p
		}
	}
	return paths[0]
}

// recordTrap updates visitor state for a request inside the trap area.
func (s *Server) recordTrap(id who, kind trap.Kind, p string) store.Visitor {
	now := s.now()
	newly := ""
	v := s.store.Update(id.visitor, now, func(v *store.Visitor) {
		wasTrapped := v.Trapped
		switch kind {
		case trap.Shared:
			v.SharedHits++
			v.Trapped = true
		default:
			v.OwnHits++
			if v.OwnHits >= 2 {
				v.Trapped = true
			}
		}
		if v.Trapped && !wasTrapped {
			v.TrappedAt = now
			newly = "repeat"
			if kind == trap.Shared {
				newly = "shared"
			}
		}
	})
	s.mTrapHits.Inc(kind.String())
	s.log.Info("trap hit", "ip", id.ip.String(), "ua", clip(id.ua), "path", clip(p),
		"kind", kind.String(), "own_hits", v.OwnHits, "shared_hits", v.SharedHits)
	if newly != "" {
		s.mTrapped.Inc(newly)
		s.log.Warn("visitor trapped", "ip", id.ip.String(), "ua", clip(id.ua), "cause", newly)
	}
	return v
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	id := s.identify(r)
	now := s.now()
	rate := s.store.Hit(id.addrKey, now, s.cfg.RateWindow)

	var v store.Visitor
	if orig := originalPath(r); orig != "" && s.traps.InArea(orig) {
		// The proxy sent a trap request through /check instead of routing it
		// to us: count it all the same.
		v = s.recordTrap(id, s.traps.Classify(id.addrKey, orig), orig)
	} else {
		v, _ = s.store.Touch(id.visitor, now)
	}

	res := verdict.Evaluate(verdict.Input{
		Visitor:   v,
		Rate:      rate,
		RateMax:   s.cfg.RateMax,
		UserAgent: id.ua,
		Bot:       s.bots.Check(id.ua, id.ip),
	}, s.cfg.SuspectScore)

	h := w.Header()
	h.Set(HeaderVerdict, string(res.Verdict))
	h.Set(HeaderScore, strconv.Itoa(res.Score))
	if len(res.Reasons) > 0 {
		h.Set(HeaderReasons, strings.Join(res.Reasons, ","))
	}
	h.Set("Cache-Control", "no-store")
	s.mChecks.Inc(string(res.Verdict))

	status := http.StatusOK
	if s.cfg.Mode == config.ModeEnforce && res.Verdict == verdict.Trapped {
		status = s.cfg.EnforceStatus
		s.mEnforcements.Inc(string(res.Verdict))
	}
	if res.Verdict != verdict.Clean {
		s.log.Debug("check", "ip", id.ip.String(), "ua", clip(id.ua), "verdict", string(res.Verdict),
			"score", res.Score, "reasons", strings.Join(res.Reasons, ","), "status", status)
	}
	w.WriteHeader(status)
}

// originalPath returns the path of the request being authorised, as sent by
// the proxy: X-Forwarded-Uri (Caddy, Traefik) or X-Original-URI (nginx).
func originalPath(r *http.Request) string {
	raw := r.Header.Get("X-Forwarded-Uri")
	if raw == "" {
		raw = r.Header.Get("X-Original-URI")
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return ""
	}
	return u.Path
}

func clip(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
