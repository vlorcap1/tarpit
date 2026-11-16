// Package goodbot verifies crawlers that claim to be well-known search engines
// using forward-confirmed reverse DNS.
//
// Verification runs in the background so that a forward-auth request never
// waits on DNS: the first request from a claimed crawler gets StatusPending,
// and later requests see the cached result.
package goodbot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vlorcap1/telarana/internal/config"
)

// Status is the verification result for one (crawler, address) pair.
type Status int

const (
	// NotClaimed: the User-Agent does not claim to be a known crawler.
	NotClaimed Status = iota
	// Pending: verification has not finished (or failed transiently).
	Pending
	// Verified: reverse and forward DNS confirm the claim.
	Verified
	// Impostor: DNS definitively contradicts the claim.
	Impostor
)

func (s Status) String() string {
	return [...]string{"not-claimed", "pending", "verified", "impostor"}[s]
}

// Resolver is the subset of *net.Resolver used here (replaceable in tests).
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

const (
	definitiveTTL = 24 * time.Hour
	transientTTL  = time.Minute
	maxCache      = 50_000
)

type entry struct {
	status  Status
	expires time.Time
}

// Verifier checks crawler claims. It is safe for concurrent use.
type Verifier struct {
	bots     []config.GoodBot
	resolver Resolver
	timeout  time.Duration
	now      func() time.Time
	onResult func(bot string, s Status)

	mu       sync.Mutex
	cache    map[string]entry
	inflight map[string]bool
	wg       sync.WaitGroup
}

// New returns a Verifier. onResult (may be nil) is called once per completed
// verification, e.g. for logging and metrics.
func New(bots []config.GoodBot, r Resolver, timeout time.Duration, onResult func(string, Status)) *Verifier {
	if r == nil {
		r = net.DefaultResolver
	}
	return &Verifier{
		bots: bots, resolver: r, timeout: timeout, now: time.Now, onResult: onResult,
		cache: make(map[string]entry), inflight: make(map[string]bool),
	}
}

// Claimed returns the crawler a User-Agent claims to be, if any.
func (v *Verifier) Claimed(userAgent string) (config.GoodBot, bool) {
	ua := strings.ToLower(userAgent)
	for _, b := range v.bots {
		if strings.Contains(ua, b.Name) {
			return b, true
		}
	}
	return config.GoodBot{}, false
}

// Check returns the status for a User-Agent and address, starting a
// background verification when there is no cached answer.
func (v *Verifier) Check(userAgent string, addr netip.Addr) Status {
	bot, ok := v.Claimed(userAgent)
	if !ok {
		return NotClaimed
	}
	key := bot.Name + "|" + addr.String()
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.cache[key]; ok && now.Before(e.expires) {
		return e.status
	}
	if !v.inflight[key] {
		v.inflight[key] = true
		v.wg.Add(1)
		go v.verify(key, bot, addr)
	}
	return Pending
}

// Wait blocks until in-flight verifications finish (used in tests and on
// shutdown).
func (v *Verifier) Wait() { v.wg.Wait() }

func (v *Verifier) verify(key string, bot config.GoodBot, addr netip.Addr) {
	defer v.wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	status, definitive := v.lookup(ctx, bot, addr)
	ttl := transientTTL
	if definitive {
		ttl = definitiveTTL
	}

	v.mu.Lock()
	delete(v.inflight, key)
	if len(v.cache) >= maxCache {
		for k := range v.cache { // drop an arbitrary entry
			delete(v.cache, k)
			break
		}
	}
	v.cache[key] = entry{status: status, expires: v.now().Add(ttl)}
	v.mu.Unlock()

	if v.onResult != nil {
		v.onResult(bot.Name, status)
	}
}

// lookup performs forward-confirmed reverse DNS. definitive is false when a
// DNS failure was transient, so the answer should not be cached for long.
func (v *Verifier) lookup(ctx context.Context, bot config.GoodBot, addr netip.Addr) (Status, bool) {
	hosts, err := v.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		if isNotFound(err) {
			return Impostor, true
		}
		return Pending, false
	}
	transient := false
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !hasSuffix(h, bot.Suffixes) {
			continue
		}
		ips, err := v.resolver.LookupNetIP(ctx, "ip", h)
		if err != nil {
			if !isNotFound(err) {
				transient = true
			}
			continue
		}
		for _, ip := range ips {
			if ip.Unmap() == addr {
				return Verified, true
			}
		}
	}
	if transient {
		return Pending, false
	}
	return Impostor, true
}

func hasSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}
