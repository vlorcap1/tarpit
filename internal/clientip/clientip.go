// Package clientip extracts the real client address from a request that may
// have passed through trusted reverse proxies, and derives the key used to
// group addresses (IPv6 clients are grouped by /64, since a single host can
// rotate through a whole /64).
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// FromRequest returns the client IP. Forwarding headers are only honoured
// when the direct peer is a trusted proxy; X-Forwarded-For is then walked
// right to left, skipping trusted hops, so a client cannot spoof its address
// by sending its own X-Forwarded-For.
func FromRequest(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parse(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}

	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	var leftmost netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		a := parse(hops[i])
		if !a.IsValid() {
			// Garbage in the chain: stop rather than trust anything left of it.
			break
		}
		leftmost = a
		if !isTrusted(a, trusted) {
			return a
		}
	}
	if leftmost.IsValid() {
		return leftmost // every hop was trusted: the client is on our network
	}
	if a := parse(r.Header.Get("X-Real-IP")); a.IsValid() {
		return a
	}
	return peer
}

// Key groups addresses: the full address for IPv4, the /64 for IPv6.
func Key(a netip.Addr) string {
	if !a.IsValid() {
		return "invalid"
	}
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

func parse(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
