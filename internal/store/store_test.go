package store

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestUpdateTouchGet(t *testing.T) {
	m := NewMemory(100)
	if _, ok := m.Touch("a", t0); ok {
		t.Fatal("Touch must not create visitors")
	}
	v := m.Update("a", t0, func(v *Visitor) { v.OwnHits++ })
	if v.OwnHits != 1 || m.Len() != 1 {
		t.Fatalf("update failed: %+v", v)
	}
	v.OwnHits = 99 // a copy: must not leak back
	got, _ := m.Get("a")
	if got.OwnHits != 1 {
		t.Fatal("Update must return a copy")
	}
	got, ok := m.Touch("a", t0.Add(time.Minute))
	if !ok || !got.LastSeen.Equal(t0.Add(time.Minute)) {
		t.Fatalf("touch: %+v %v", got, ok)
	}
}

func TestHitSlidingWindow(t *testing.T) {
	m := NewMemory(100)
	w := 10 * time.Second
	for i := 0; i < 20; i++ {
		m.Hit("ip", t0.Add(time.Duration(i)*100*time.Millisecond), w)
	}
	if n := m.Hit("ip", t0.Add(2*time.Second), w); n != 21 {
		t.Errorf("same window: got %d, want 21", n)
	}
	// Halfway into the next window, about half of the previous one counts.
	if n := m.Hit("ip", t0.Add(15*time.Second), w); n < 9 || n > 13 {
		t.Errorf("next window: got %d, want ~11", n)
	}
	// Long idle: everything is forgotten.
	if n := m.Hit("ip", t0.Add(time.Hour), w); n != 1 {
		t.Errorf("after idle: got %d, want 1", n)
	}
}

func TestSweepAndCap(t *testing.T) {
	m := NewMemory(100)
	m.Update("old", t0, nil)
	m.Update("new", t0.Add(2*time.Hour), nil)
	m.Hit("oldip", t0, time.Second)
	m.Sweep(t0.Add(2*time.Hour), time.Hour)
	if _, ok := m.Get("old"); ok {
		t.Error("old visitor not swept")
	}
	if _, ok := m.Get("new"); !ok {
		t.Error("new visitor swept")
	}
	if len(m.rates) != 0 {
		t.Error("old rate not swept")
	}

	for i := 0; i < 1000; i++ {
		m.Update(fmt.Sprint(i), t0, nil)
	}
	if m.Len() > 100 {
		t.Errorf("cap exceeded: %d", m.Len())
	}
}
