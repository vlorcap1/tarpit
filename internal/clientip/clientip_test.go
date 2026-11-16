package clientip

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

var trusted = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
}

func TestFromRequest(t *testing.T) {
	cases := []struct {
		name, peer, xff, realIP, want string
	}{
		{"untrusted peer ignores headers", "203.0.113.9:4000", "1.2.3.4", "", "203.0.113.9"},
		{"trusted peer uses XFF", "10.0.0.2:4000", "1.2.3.4", "", "1.2.3.4"},
		{"client cannot spoof by prepending", "10.0.0.2:4000", "6.6.6.6, 1.2.3.4", "", "1.2.3.4"},
		{"skips trusted hops", "10.0.0.2:4000", "1.2.3.4, 10.0.0.7", "", "1.2.3.4"},
		{"garbage stops the walk", "10.0.0.2:4000", "1.2.3.4, nonsense", "", "10.0.0.2"},
		{"falls back to X-Real-IP", "10.0.0.2:4000", "", "1.2.3.4", "1.2.3.4"},
		{"all hops trusted", "10.0.0.2:4000", "10.0.0.9", "", "10.0.0.9"},
		{"ipv6 peer", "[2001:db8::1]:4000", "", "", "2001:db8::1"},
		{"ipv4-mapped is unmapped", "10.0.0.2:4000", "::ffff:1.2.3.4", "", "1.2.3.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.peer
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if c.realIP != "" {
				r.Header.Set("X-Real-IP", c.realIP)
			}
			if got := FromRequest(r, trusted); got.String() != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestKey(t *testing.T) {
	if k := Key(netip.MustParseAddr("1.2.3.4")); k != "1.2.3.4" {
		t.Errorf("ipv4 key = %s", k)
	}
	a := Key(netip.MustParseAddr("2001:db8:1:2::1"))
	b := Key(netip.MustParseAddr("2001:db8:1:2:ffff::9"))
	c := Key(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a != "2001:db8:1:2::/64" || a == c {
		t.Errorf("ipv6 keys: %s %s %s", a, b, c)
	}
}
