package config

import (
	"strings"
	"testing"
	"time"
)

const goodSecret = "0123456789abcdef0123456789abcdef"

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(map[string]string{"TELARANA_SECRET": goodSecret}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeObserve {
		t.Errorf("default mode = %q, want observe", c.Mode)
	}
	if c.TrapPrefix != "/restricted" || c.Listen != ":8080" || c.AdminListen != ":9090" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.EnforceStatus != 403 || c.SuspectScore != 50 || c.RateWindow != 10*time.Second {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if len(c.TrustedProxies) != len(DefaultTrustedProxies) || len(c.GoodBots) != len(DefaultGoodBots) {
		t.Errorf("trusted proxies / good bots not defaulted")
	}
}

func TestSecretValidation(t *testing.T) {
	for name, secret := range map[string]string{
		"missing":     "",
		"placeholder": placeholderSecret,
		"short":       "too-short",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FromEnv(env(map[string]string{"TELARANA_SECRET": secret}))
			if err == nil || !strings.Contains(err.Error(), "TELARANA_SECRET") {
				t.Fatalf("want secret error, got %v", err)
			}
		})
	}
}

func TestInvalidValuesAreAllReported(t *testing.T) {
	_, err := FromEnv(env(map[string]string{
		"TELARANA_SECRET":          goodSecret,
		"TELARANA_MODE":            "block",
		"TELARANA_TRAP_PREFIX":     "/check",
		"TELARANA_RATE_WINDOW":     "-1s",
		"TELARANA_ENFORCE_STATUS":  "200",
		"TELARANA_TRUSTED_PROXIES": "not-an-ip",
	}))
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"TELARANA_MODE", "TELARANA_TRAP_PREFIX", "TELARANA_RATE_WINDOW",
		"TELARANA_ENFORCE_STATUS", "TELARANA_TRUSTED_PROXIES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestValidPrefix(t *testing.T) {
	for p, want := range map[string]bool{
		"/restricted": true, "/a/b-c_d.e": true, "/x": true,
		"": false, "/": false, "restricted": false, "/a{b}": false, "/a b": false,
		"/a//b": false, "/../x": false, "/healthz": false, "/ROBOTS.TXT": false, "/a?b": false,
	} {
		if got := validPrefix(p); got != want {
			t.Errorf("validPrefix(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestTrustedProxiesAndGoodBots(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"TELARANA_SECRET":          goodSecret,
		"TELARANA_TRUSTED_PROXIES": "10.1.2.3, 172.20.0.0/16",
		"TELARANA_GOOD_BOTS":       "mybot:example.org|.example.net; other:.other.io",
		"TELARANA_ADMIN_LISTEN":    "off",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[0].Bits() != 32 {
		t.Errorf("trusted proxies = %v", c.TrustedProxies)
	}
	if c.AdminListen != "" {
		t.Errorf("admin listener should be disabled")
	}
	extra := c.GoodBots[len(DefaultGoodBots):]
	if len(extra) != 2 || extra[0].Name != "mybot" || extra[0].Suffixes[0] != ".example.org" {
		t.Errorf("good bots = %+v", extra)
	}
	if _, err := ParseGoodBots("broken"); err == nil {
		t.Error("want error for entry without suffixes")
	}
}
