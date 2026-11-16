// Package store keeps per-visitor state and per-address request rates.
//
// The Store interface allows a shared backend (e.g. Redis) for multi-instance
// deployments; Memory is the built-in single-instance implementation.
package store

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Visitor is what Telaraña remembers about one visitor (address + User-Agent).
type Visitor struct {
	OwnHits    int       // trap paths issued to this visitor that it requested
	SharedHits int       // trap paths issued to someone else that it requested
	Trapped    bool      // confirmed: second own hit, or any shared hit
	TrappedAt  time.Time // when it became trapped
	LastSeen   time.Time
}

// Store is the state backend.
type Store interface {
	// Update applies fn to the visitor under key (creating it if needed)
	// atomically and returns a copy of the result.
	Update(key string, now time.Time, fn func(v *Visitor)) Visitor
	// Get returns a copy of the visitor under key.
	Get(key string) (Visitor, bool)
	// Touch refreshes LastSeen of an existing visitor and returns a copy of
	// it. Unlike Update it never creates one, so clean traffic costs no state.
	Touch(key string, now time.Time) (Visitor, bool)
	// Hit records one request for an address key and returns the estimated
	// number of requests from it within the sliding window.
	Hit(addrKey string, now time.Time, window time.Duration) int
	// Sweep forgets entries idle for longer than ttl.
	Sweep(now time.Time, ttl time.Duration)
	// Len returns the number of tracked visitors.
	Len() int
}

type rate struct {
	start      time.Time
	curr, prev int
	last       time.Time
}

// Memory is an in-process Store. It is safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	visitors map[string]*Visitor
	rates    map[string]*rate
	max      int
}

// NewMemory returns a Memory store tracking at most max visitors (and max
// addresses). When full, a random ~1% of entries is evicted.
func NewMemory(max int) *Memory {
	return &Memory{visitors: make(map[string]*Visitor), rates: make(map[string]*rate), max: max}
}

// Update implements Store.
func (m *Memory) Update(key string, now time.Time, fn func(v *Visitor)) Visitor {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.visitors[key]
	if !ok {
		if len(m.visitors) >= m.max {
			evict(m.visitors, m.max)
		}
		v = &Visitor{}
		m.visitors[key] = v
	}
	v.LastSeen = now
	if fn != nil {
		fn(v)
	}
	return *v
}

// Get implements Store.
func (m *Memory) Get(key string) (Visitor, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.visitors[key]
	if !ok {
		return Visitor{}, false
	}
	return *v, true
}

// Touch implements Store.
func (m *Memory) Touch(key string, now time.Time) (Visitor, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.visitors[key]
	if !ok {
		return Visitor{}, false
	}
	v.LastSeen = now
	return *v, true
}

// Hit implements Store with a sliding-window approximation: the previous
// window's count is weighted by how much of it still overlaps the window.
func (m *Memory) Hit(addrKey string, now time.Time, window time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rates[addrKey]
	if !ok {
		if len(m.rates) >= m.max {
			evict(m.rates, m.max)
		}
		r = &rate{start: now}
		m.rates[addrKey] = r
	}
	if el := now.Sub(r.start); el >= window {
		if el >= 2*window {
			r.prev = 0
		} else {
			r.prev = r.curr
		}
		r.curr = 0
		r.start = now.Add(-(el % window))
	}
	r.curr++
	r.last = now
	weight := 1 - float64(now.Sub(r.start))/float64(window)
	if weight < 0 {
		weight = 0
	}
	return r.curr + int(float64(r.prev)*weight)
}

// Sweep implements Store.
func (m *Memory) Sweep(now time.Time, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.visitors {
		if now.Sub(v.LastSeen) > ttl {
			delete(m.visitors, k)
		}
	}
	for k, r := range m.rates {
		if now.Sub(r.last) > ttl {
			delete(m.rates, k)
		}
	}
}

// Len implements Store.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.visitors)
}

// evict removes a random ~1% (at least one) of entries. Map iteration order
// is already randomised; the extra shuffle keeps it independent of that
// implementation detail.
func evict[T any](mp map[string]T, max int) {
	n := max / 100
	if n < 1 {
		n = 1
	}
	keys := make([]string, 0, len(mp))
	for k := range mp {
		keys = append(keys, k)
	}
	rand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
	for _, k := range keys[:min(n, len(keys))] {
		delete(mp, k)
	}
}
