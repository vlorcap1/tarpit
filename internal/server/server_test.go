package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/vlorcap1/telarana/internal/config"
)

const proxyAddr = "10.0.0.2:5555" // a trusted proxy (private range)

type noDNS struct{}

func (noDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}
func (noDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

type googleDNS struct{}

func (googleDNS) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"crawl-66-249-66-1.googlebot.com."}, nil
}
func (googleDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("66.249.66.1")}, nil
}

func newServer(t *testing.T, mode config.Mode, opt Options) *Server {
	t.Helper()
	cfg, err := config.FromEnv(func(k string) string {
		return map[string]string{
			"TELARANA_SECRET": "0123456789abcdef0123456789abcdef",
			"TELARANA_MODE":   string(mode),
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Resolver == nil {
		opt.Resolver = noDNS{}
	}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opt)
}

type req struct {
	method, path, client, ua string
	headers                  map[string]string
}

func do(h http.Handler, r req) *httptest.ResponseRecorder {
	if r.method == "" {
		r.method = "GET"
	}
	if r.ua == "" {
		r.ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
	}
	hr := httptest.NewRequest(r.method, r.path, nil)
	hr.RemoteAddr = proxyAddr
	hr.Header.Set("X-Forwarded-For", r.client)
	hr.Header.Set("User-Agent", r.ua)
	for k, v := range r.headers {
		hr.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return w
}

var disallowRe = regexp.MustCompile(`(?m)^Disallow: (\S+)$`)

func trapsFor(t *testing.T, h http.Handler, client string) []string {
	t.Helper()
	w := do(h, req{path: "/robots.txt", client: client})
	if w.Code != 200 {
		t.Fatalf("robots.txt status %d", w.Code)
	}
	var out []string
	for _, m := range disallowRe.FindAllStringSubmatch(w.Body.String(), -1) {
		// only per-visitor traps: skip the site's rules and the area itself
		if strings.HasPrefix(m[1], "/restricted/") && m[1] != "/restricted/" {
			out = append(out, m[1])
		}
	}
	return out
}

func check(h http.Handler, client string, extra map[string]string) *httptest.ResponseRecorder {
	return do(h, req{path: "/check", client: client, headers: extra})
}

func TestRobotsTxt(t *testing.T) {
	s := newServer(t, config.ModeObserve, Options{RobotsBase: "User-agent: *\nDisallow: /admin/"})
	h := s.PublicHandler()
	w := do(h, req{path: "/robots.txt", client: "1.1.1.1"})
	body := w.Body.String()
	if !strings.HasPrefix(body, "User-agent: *\nDisallow: /admin/\n") {
		t.Errorf("site robots.txt not preserved:\n%s", body)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "private") || !strings.Contains(cc, "no-store") {
		t.Errorf("robots.txt must not be cacheable by shared caches, got %q", cc)
	}
	if !strings.Contains(body, "\nDisallow: /restricted/\n") {
		t.Errorf("the whole trap area must be disallowed:\n%s", body)
	}
	a, b := trapsFor(t, h, "1.1.1.1"), trapsFor(t, h, "2.2.2.2")
	if len(a) != 3 || a[0] == b[0] {
		t.Errorf("traps not per visitor: %v vs %v", a, b)
	}
}

func TestDoubleDoorThenTrapped(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeObserve, config.ModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			s := newServer(t, mode, Options{})
			h := s.PublicHandler()
			const bot = "203.0.113.7"
			paths := trapsFor(t, h, bot)

			if w := check(h, bot, nil); w.Header().Get(HeaderVerdict) != "clean" || w.Code != 200 {
				t.Fatalf("before traps: %d %s", w.Code, w.Header().Get(HeaderVerdict))
			}

			// First door: a decoy page that links to another trap.
			w := do(h, req{path: paths[0], client: bot})
			if w.Code != 200 || !strings.Contains(w.Body.String(), `href="`+paths[1]+`"`) {
				t.Fatalf("decoy: %d %s", w.Code, w.Body.String())
			}
			if v := check(h, bot, nil).Header().Get(HeaderVerdict); v != "suspect" {
				t.Fatalf("after first hit: verdict %s, want suspect", v)
			}

			// Second door: confirmed.
			if w := do(h, req{path: paths[1], client: bot}); w.Code != 404 {
				t.Fatalf("second trap: status %d, want 404", w.Code)
			}
			w = check(h, bot, nil)
			if w.Header().Get(HeaderVerdict) != "trapped" || w.Header().Get(HeaderScore) != "100" {
				t.Fatalf("after second hit: %v", w.Header())
			}
			want := 200
			if mode == config.ModeEnforce {
				want = 403
			}
			if w.Code != want {
				t.Errorf("status %d, want %d", w.Code, want)
			}

			// Same IP, different browser: unaffected (shared IPs, NAT).
			other := do(h, req{path: "/check", client: bot, ua: "Mozilla/5.0 (Macintosh) Safari/605"})
			if other.Header().Get(HeaderVerdict) != "clean" || other.Code != 200 {
				t.Errorf("neighbour on same IP: %d %s", other.Code, other.Header().Get(HeaderVerdict))
			}
		})
	}
}

func TestLinkTrap(t *testing.T) {
	// A static hidden link in the site's pages, e.g. <a href="/restricted/archive" hidden>,
	// catches link-following crawlers that never read robots.txt.
	s := newServer(t, config.ModeEnforce, Options{})
	h := s.PublicHandler()
	const bot = "203.0.113.20"
	w := do(h, req{path: "/restricted/archive", client: bot})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "href=") {
		t.Fatalf("link trap first hit: %d", w.Code)
	}
	next := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	do(h, req{path: next, client: bot})
	if w := check(h, bot, nil); w.Code != 403 {
		t.Errorf("link-following crawler not trapped: %d %v", w.Code, w.Header())
	}
}

func TestSharedTrapIsImmediatelyTrapped(t *testing.T) {
	s := newServer(t, config.ModeEnforce, Options{})
	h := s.PublicHandler()
	leaked := trapsFor(t, h, "198.51.100.1")[0]
	if w := do(h, req{path: leaked, client: "198.51.100.99"}); w.Code != 404 {
		t.Errorf("shared trap: status %d, want 404", w.Code)
	}
	if w := check(h, "198.51.100.99", nil); w.Code != 403 || w.Header().Get(HeaderReasons) != "trap:shared" {
		t.Errorf("shared: %d %v", w.Code, w.Header())
	}
}

func TestIPv6RotationWithinSlash64IsNotShared(t *testing.T) {
	s := newServer(t, config.ModeObserve, Options{})
	h := s.PublicHandler()
	p := trapsFor(t, h, "2001:db8:1:2::1")[0]
	do(h, req{path: p, client: "2001:db8:1:2::abcd"})
	w := check(h, "2001:db8:1:2::abcd", nil)
	if r := w.Header().Get(HeaderReasons); r != "trap:first-hit" {
		t.Errorf("reasons = %q, want trap:first-hit (own, not shared)", r)
	}
}

func TestCheckCountsTrapRequestsSentThroughForwardAuth(t *testing.T) {
	// Traefik-style setups may send everything through /check.
	s := newServer(t, config.ModeEnforce, Options{})
	h := s.PublicHandler()
	const bot = "203.0.113.8"
	paths := trapsFor(t, h, bot)
	check(h, bot, map[string]string{"X-Forwarded-Uri": paths[0] + "?x=1"})
	w := check(h, bot, map[string]string{"X-Original-URI": paths[1]})
	if w.Code != 403 || w.Header().Get(HeaderVerdict) != "trapped" {
		t.Errorf("forward-auth trap requests: %d %s", w.Code, w.Header().Get(HeaderVerdict))
	}
}

func TestCleanTrafficKeepsNoState(t *testing.T) {
	s := newServer(t, config.ModeObserve, Options{})
	h := s.PublicHandler()
	for i := 0; i < 50; i++ {
		check(h, "192.0.2.1", map[string]string{"X-Forwarded-Uri": "/blog/post"})
	}
	if n := s.Store().Len(); n != 0 {
		t.Errorf("clean traffic created %d visitor entries", n)
	}
}

func TestSpoofedForwardedForFromUntrustedPeer(t *testing.T) {
	s := newServer(t, config.ModeEnforce, Options{})
	h := s.PublicHandler()
	victim := "198.51.100.50"
	paths := trapsFor(t, h, victim)

	// An attacker connecting directly (not via the proxy) claims to be the
	// victim. Its requests must be attributed to its own address.
	for _, p := range paths[:2] {
		r := httptest.NewRequest("GET", p, nil)
		r.RemoteAddr = "203.0.113.66:1234"
		r.Header.Set("X-Forwarded-For", victim)
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if w := check(h, victim, nil); w.Header().Get(HeaderVerdict) != "clean" {
		t.Errorf("victim framed: %s", w.Header().Get(HeaderVerdict))
	}
}

func TestVerifiedCrawlerIsNeverPenalised(t *testing.T) {
	s := newServer(t, config.ModeEnforce, Options{Resolver: googleDNS{}})
	h := s.PublicHandler()
	const ip, ua = "66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	first := do(h, req{path: "/check", client: ip, ua: ua})
	if first.Header().Get(HeaderVerdict) != "clean" {
		t.Errorf("while pending: %s", first.Header().Get(HeaderVerdict))
	}
	s.Bots().Wait()
	for _, p := range trapsFor(t, h, ip)[:2] {
		do(h, req{path: p, client: ip, ua: ua})
	}
	w := do(h, req{path: "/check", client: ip, ua: ua})
	if w.Code != 200 || w.Header().Get(HeaderVerdict) != "verified-bot" {
		t.Errorf("verified crawler: %d %s", w.Code, w.Header().Get(HeaderVerdict))
	}
}

func TestImpostorCrawlerIsSuspect(t *testing.T) {
	s := newServer(t, config.ModeEnforce, Options{})
	h := s.PublicHandler()
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1)"
	do(h, req{path: "/check", client: "203.0.113.9", ua: ua})
	s.Bots().Wait()
	w := do(h, req{path: "/check", client: "203.0.113.9", ua: ua})
	if w.Code != 200 || w.Header().Get(HeaderVerdict) != "suspect" {
		t.Errorf("impostor: %d %s (suspects are reported, not blocked)", w.Code, w.Header().Get(HeaderVerdict))
	}
}

func TestMetricsAndHealth(t *testing.T) {
	s := newServer(t, config.ModeObserve, Options{})
	pub, admin := s.PublicHandler(), s.AdminHandler()
	p := trapsFor(t, pub, "203.0.113.1")
	do(pub, req{path: p[0], client: "203.0.113.1"})
	do(pub, req{path: p[1], client: "203.0.113.1"})
	check(pub, "203.0.113.1", nil)

	w := httptest.NewRecorder()
	admin.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		`telarana_trap_hits_total{kind="own"} 2`,
		`telarana_trapped_total{cause="repeat"} 1`,
		`telarana_checks_total{verdict="trapped"} 1`,
		`telarana_checks_total{verdict="clean"} 0`,
		`telarana_robots_served_total{status="ok"} 1`,
		"telarana_visitors_tracked 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if w := do(pub, req{path: "/metrics", client: "1.2.3.4"}); w.Code != 404 {
		t.Errorf("/metrics must not be on the public listener, got %d", w.Code)
	}
	for _, h := range []http.Handler{pub, admin} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
		if w.Code != 200 {
			t.Errorf("healthz status %d", w.Code)
		}
	}
}
