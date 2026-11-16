package trap

import (
	"strings"
	"testing"
)

var (
	secret   = []byte("0123456789abcdef0123456789abcdef")
	previous = []byte("fedcba9876543210fedcba9876543210")
)

func TestPathsAreStableDistinctAndPerVisitor(t *testing.T) {
	tr := New("/restricted", secret, nil)
	a1, a2, b := tr.Paths("1.1.1.1"), tr.Paths("1.1.1.1"), tr.Paths("2.2.2.2")
	if len(a1) != PerVisitor {
		t.Fatalf("got %d paths, want %d", len(a1), PerVisitor)
	}
	seen := map[string]bool{}
	for i, p := range a1 {
		if p != a2[i] {
			t.Errorf("paths not stable: %s vs %s", p, a2[i])
		}
		if seen[p] {
			t.Errorf("duplicate path %s", p)
		}
		seen[p] = true
		if !strings.HasPrefix(p, "/restricted/") {
			t.Errorf("path %s outside prefix", p)
		}
	}
	for _, p := range b {
		if seen[p] {
			t.Errorf("visitors share path %s", p)
		}
	}
}

func TestClassify(t *testing.T) {
	tr := New("/restricted", secret, nil)
	own := tr.Paths("1.1.1.1")[0]
	cases := []struct {
		key, path string
		want      Kind
	}{
		{"1.1.1.1", own, Own},
		{"2.2.2.2", own, Shared},
		{"1.1.1.1", "/restricted", Own},
		{"1.1.1.1", "/restricted/admin-backup", Own},
		{"1.1.1.1", "/restricted/../public", None},
		{"1.1.1.1", "/restrictedfoo", None},
		{"1.1.1.1", "/", None},
		{"1.1.1.1", "/blog/post", None},
	}
	for _, c := range cases {
		if got := tr.Classify(c.key, c.path); got != c.want {
			t.Errorf("Classify(%s, %s) = %s, want %s", c.key, c.path, got, c.want)
		}
	}
}

func TestSecretRotation(t *testing.T) {
	old := New("/restricted", previous, nil).Paths("1.1.1.1")[0]
	rotated := New("/restricted", secret, previous)
	if got := rotated.Classify("1.1.1.1", old); got != Own {
		t.Errorf("path from previous secret = %s, want own", got)
	}
	if got := New("/restricted", secret, nil).Classify("1.1.1.1", old); got != Shared {
		t.Errorf("without rotation the old path looks shared, got %s", got)
	}
}
