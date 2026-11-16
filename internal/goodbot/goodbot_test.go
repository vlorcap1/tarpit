package goodbot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vlorcap1/telarana/internal/config"
)

// fakeDNS maps IP -> PTR hosts and host -> A/AAAA records.
type fakeDNS struct {
	ptr     map[string][]string
	fwd     map[string][]netip.Addr
	failPTR error
	calls   atomic.Int32
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls.Add(1)
	if f.failPTR != nil {
		return nil, f.failPTR
	}
	if h, ok := f.ptr[addr]; ok {
		return h, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f.fwd[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func check(t *testing.T, dns *fakeDNS, ip string) Status {
	t.Helper()
	v := New(config.DefaultGoodBots, dns, time.Second, nil)
	addr := netip.MustParseAddr(ip)
	if s := v.Check(googleUA, addr); s != Pending {
		t.Fatalf("first check = %s, want pending", s)
	}
	v.Wait()
	return v.Check(googleUA, addr)
}

func TestVerification(t *testing.T) {
	real := netip.MustParseAddr("66.249.66.1")
	cases := []struct {
		name string
		dns  *fakeDNS
		ip   string
		want Status
	}{
		{"forward-confirmed", &fakeDNS{
			ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
			fwd: map[string][]netip.Addr{"crawl-66-249-66-1.googlebot.com": {real}},
		}, "66.249.66.1", Verified},
		{"wrong domain", &fakeDNS{
			ptr: map[string][]string{"6.6.6.6": {"evil.example.com."}},
		}, "6.6.6.6", Impostor},
		{"lookalike domain", &fakeDNS{
			ptr: map[string][]string{"6.6.6.6": {"crawl.notgooglebot.com."}},
			fwd: map[string][]netip.Addr{"crawl.notgooglebot.com": {netip.MustParseAddr("6.6.6.6")}},
		}, "6.6.6.6", Impostor},
		{"forward does not match", &fakeDNS{
			ptr: map[string][]string{"6.6.6.6": {"crawl-66-249-66-1.googlebot.com."}},
			fwd: map[string][]netip.Addr{"crawl-66-249-66-1.googlebot.com": {real}},
		}, "6.6.6.6", Impostor},
		{"no PTR record", &fakeDNS{}, "6.6.6.6", Impostor},
		{"DNS timeout stays pending", &fakeDNS{failPTR: errors.New("i/o timeout")}, "66.249.66.1", Pending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := check(t, c.dns, c.ip); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestNotClaimedAndCaching(t *testing.T) {
	dns := &fakeDNS{}
	v := New(config.DefaultGoodBots, dns, time.Second, nil)
	if s := v.Check("Mozilla/5.0 (Macintosh)", netip.MustParseAddr("1.2.3.4")); s != NotClaimed {
		t.Errorf("browser = %s, want not-claimed", s)
	}
	addr := netip.MustParseAddr("6.6.6.6")
	v.Check(googleUA, addr)
	v.Wait()
	for i := 0; i < 5; i++ {
		v.Check(googleUA, addr)
	}
	if n := dns.calls.Load(); n != 1 {
		t.Errorf("DNS queried %d times, want 1 (cached)", n)
	}
}
