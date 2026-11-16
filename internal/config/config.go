// Package config loads and validates Telaraña's configuration from
// environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode controls whether Telaraña only reports verdicts or also enforces them.
type Mode string

const (
	// ModeObserve always lets requests through and only adds verdict headers.
	ModeObserve Mode = "observe"
	// ModeEnforce answers /check with EnforceStatus for trapped visitors.
	ModeEnforce Mode = "enforce"
)

// GoodBot is a crawler that can be verified by forward-confirmed reverse DNS:
// its IP must resolve to a host under one of Suffixes, and that host must
// resolve back to the same IP.
type GoodBot struct {
	Name     string   // lowercase substring matched against the User-Agent
	Suffixes []string // accepted reverse-DNS suffixes, e.g. ".googlebot.com"
}

// DefaultGoodBots only lists crawlers that document reverse-DNS verification.
// Crawlers that publish IP lists instead (e.g. DuckDuckBot) are deliberately
// absent: checking them by reverse DNS would wrongly flag them as impostors.
var DefaultGoodBots = []GoodBot{
	{Name: "googlebot", Suffixes: []string{".googlebot.com", ".google.com", ".googleusercontent.com"}},
	{Name: "bingbot", Suffixes: []string{".search.msn.com"}},
	{Name: "applebot", Suffixes: []string{".applebot.apple.com"}},
	{Name: "yandexbot", Suffixes: []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
}

// DefaultTrustedProxies are loopback and private ranges: Telaraña is meant to
// sit behind a reverse proxy on a private network and never be exposed
// directly.
var DefaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
}

const placeholderSecret = "change-me"

// Config is the full runtime configuration.
type Config struct {
	Listen         string // public listener: /robots.txt, traps, /check
	AdminListen    string // private listener: /metrics, /healthz ("" disables)
	Mode           Mode
	EnforceStatus  int
	Secret         []byte
	PreviousSecret []byte // accepted for trap tokens during secret rotation
	TrapPrefix     string
	RobotsFile     string
	TrustedProxies []netip.Prefix
	GoodBots       []GoodBot
	VisitorTTL     time.Duration
	MaxVisitors    int
	RateWindow     time.Duration
	RateMax        int
	SuspectScore   int
	DNSTimeout     time.Duration
	LogLevel       slog.Level
	LogFormat      string // "json" or "text"
}

// FromEnv builds a Config from environment variables (see README for the
// full list). getenv is os.Getenv in production and a map lookup in tests.
func FromEnv(getenv func(string) string) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var errs []error

	c := &Config{
		Listen:      get("TELARANA_LISTEN", ":8080"),
		AdminListen: get("TELARANA_ADMIN_LISTEN", ":9090"),
		Mode:        Mode(strings.ToLower(get("TELARANA_MODE", string(ModeObserve)))),
		TrapPrefix:  strings.TrimRight(get("TELARANA_TRAP_PREFIX", "/restricted"), "/"),
		RobotsFile:  get("TELARANA_ROBOTS_FILE", ""),
		LogFormat:   strings.ToLower(get("TELARANA_LOG_FORMAT", "json")),
	}
	if strings.EqualFold(c.AdminListen, "off") {
		c.AdminListen = ""
	}

	secret := getenv("TELARANA_SECRET")
	switch {
	case secret == "":
		errs = append(errs, errors.New("TELARANA_SECRET is required (use at least 32 random characters, e.g. `openssl rand -hex 32`)"))
	case secret == placeholderSecret:
		errs = append(errs, errors.New("TELARANA_SECRET still has the example value; set your own"))
	case len(secret) < 32:
		errs = append(errs, errors.New("TELARANA_SECRET must be at least 32 characters"))
	}
	c.Secret = []byte(secret)
	if prev := getenv("TELARANA_SECRET_PREVIOUS"); prev != "" {
		c.PreviousSecret = []byte(prev)
	}

	if c.Mode != ModeObserve && c.Mode != ModeEnforce {
		errs = append(errs, fmt.Errorf("TELARANA_MODE must be %q or %q, got %q", ModeObserve, ModeEnforce, c.Mode))
	}
	if !validPrefix(c.TrapPrefix) {
		errs = append(errs, fmt.Errorf("TELARANA_TRAP_PREFIX must be a path like /restricted, got %q", c.TrapPrefix))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, fmt.Errorf("TELARANA_LOG_FORMAT must be json or text, got %q", c.LogFormat))
	}

	intVar := func(k string, def, min, max int) int {
		raw := get(k, strconv.Itoa(def))
		n, err := strconv.Atoi(raw)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Errorf("%s must be an integer between %d and %d, got %q", k, min, max, raw))
			return def
		}
		return n
	}
	durVar := func(k string, def time.Duration) time.Duration {
		raw := get(k, def.String())
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration like 30s or 1h, got %q", k, raw))
			return def
		}
		return d
	}
	c.EnforceStatus = intVar("TELARANA_ENFORCE_STATUS", 403, 400, 599)
	c.MaxVisitors = intVar("TELARANA_MAX_VISITORS", 100_000, 100, 100_000_000)
	c.RateMax = intVar("TELARANA_RATE_MAX", 60, 1, 1_000_000)
	c.SuspectScore = intVar("TELARANA_SUSPECT_SCORE", 50, 1, 100)
	c.VisitorTTL = durVar("TELARANA_VISITOR_TTL", 24*time.Hour)
	c.RateWindow = durVar("TELARANA_RATE_WINDOW", 10*time.Second)
	c.DNSTimeout = durVar("TELARANA_DNS_TIMEOUT", 2*time.Second)

	if err := c.LogLevel.UnmarshalText([]byte(get("TELARANA_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("TELARANA_LOG_LEVEL: %w", err))
	}

	proxies := DefaultTrustedProxies
	if raw := getenv("TELARANA_TRUSTED_PROXIES"); strings.TrimSpace(raw) != "" {
		proxies = splitList(raw, ",")
	}
	for _, p := range proxies {
		pfx, err := parsePrefix(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("TELARANA_TRUSTED_PROXIES: %w", err))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, pfx)
	}

	c.GoodBots = append(c.GoodBots, DefaultGoodBots...)
	if raw := getenv("TELARANA_GOOD_BOTS"); strings.TrimSpace(raw) != "" {
		extra, err := ParseGoodBots(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("TELARANA_GOOD_BOTS: %w", err))
		}
		c.GoodBots = append(c.GoodBots, extra...)
	}

	if c.RobotsFile != "" {
		if _, err := os.Stat(c.RobotsFile); err != nil {
			errs = append(errs, fmt.Errorf("TELARANA_ROBOTS_FILE: %w", err))
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// ParseGoodBots parses "name:.suffix1|.suffix2;name2:.suffix3".
func ParseGoodBots(raw string) ([]GoodBot, error) {
	var out []GoodBot
	for _, entry := range splitList(raw, ";") {
		name, sfx, ok := strings.Cut(entry, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" {
			return nil, fmt.Errorf("entry %q must look like name:.example.com", entry)
		}
		bot := GoodBot{Name: name}
		for _, s := range splitList(sfx, "|") {
			s = strings.ToLower(s)
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			bot.Suffixes = append(bot.Suffixes, s)
		}
		if len(bot.Suffixes) == 0 {
			return nil, fmt.Errorf("entry %q has no domain suffixes", entry)
		}
		out = append(out, bot)
	}
	return out, nil
}

// validPrefix accepts paths like /restricted or /a/b-c_d.e (no wildcards,
// query strings or reserved names), so the prefix is safe to route on.
func validPrefix(p string) bool {
	if len(p) < 2 || p[0] != '/' || strings.Contains(p, "//") || strings.Contains(p, "..") {
		return false
	}
	for _, r := range p[1:] {
		ok := r == '/' || r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	switch strings.ToLower(p) {
	case "/check", "/healthz", "/robots.txt", "/metrics":
		return false
	}
	return true
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func splitList(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
