// Package metrics is a tiny, dependency-free Prometheus text exposition
// for the handful of counters Telaraña exports.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// CounterVec is a counter with a single label.
type CounterVec struct {
	name, help, label string
	mu                sync.RWMutex
	values            map[string]*atomic.Uint64
}

// Inc increments the counter for a label value.
func (c *CounterVec) Inc(value string) {
	c.mu.RLock()
	v, ok := c.values[value]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if v, ok = c.values[value]; !ok {
			v = new(atomic.Uint64)
			c.values[value] = v
		}
		c.mu.Unlock()
	}
	v.Add(1)
}

// Value returns the current count for a label value.
func (c *CounterVec) Value(value string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if v, ok := c.values[value]; ok {
		return v.Load()
	}
	return 0
}

type gauge struct {
	name, help string
	fn         func() float64
}

// Registry holds the exported metrics.
type Registry struct {
	mu       sync.Mutex
	counters []*CounterVec
	gauges   []gauge
}

// Counter registers a counter with one label. initial label values are
// exported as 0 from the start, so dashboards and alerts see the series.
func (r *Registry) Counter(name, help, label string, initial ...string) *CounterVec {
	c := &CounterVec{name: name, help: help, label: label, values: make(map[string]*atomic.Uint64)}
	for _, v := range initial {
		c.values[v] = new(atomic.Uint64)
	}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// Gauge registers a gauge computed on scrape.
func (r *Registry) Gauge(name, help string, fn func() float64) {
	r.mu.Lock()
	r.gauges = append(r.gauges, gauge{name, help, fn})
	r.mu.Unlock()
}

// WriteTo writes the Prometheus text format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder
	r.mu.Lock()
	counters := append([]*CounterVec(nil), r.counters...)
	gauges := append([]gauge(nil), r.gauges...)
	r.mu.Unlock()

	for _, c := range counters {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		c.mu.RLock()
		keys := make([]string, 0, len(c.values))
		for k := range c.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s{%s=%q} %d\n", c.name, c.label, k, c.values[k].Load())
		}
		c.mu.RUnlock()
	}
	for _, g := range gauges {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", g.name, g.help, g.name, g.name, g.fn())
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}
