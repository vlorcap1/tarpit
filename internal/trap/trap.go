// Package trap generates and recognises robots.txt trap paths.
//
// Every visitor (keyed by IP, or IPv6 /64) gets its own set of Disallow paths,
// signed with HMAC. A well-behaved crawler never requests them and a human
// never sees them. Requesting your own trap path means you read robots.txt and
// went exactly where it told you not to. Requesting a trap path signed for a
// *different* address means the path was obtained from somewhere else, which
// typically happens when scrapers share or replay crawl lists.
package trap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// Kind classifies a requested path.
type Kind int

const (
	// None: the path is not a trap.
	None Kind = iota
	// Own: a trap issued to this visitor (or the bare trap area).
	Own
	// Shared: a trap path that was issued to a different address.
	Shared
)

func (k Kind) String() string {
	switch k {
	case Own:
		return "own"
	case Shared:
		return "shared"
	default:
		return "none"
	}
}

const tokenLen = 16 // hex characters

// Names look like things a content harvester or vulnerability scanner wants.
var Names = []string{
	"admin-backup", "db-dump.sql", "export-users.json", "env.bak",
	"config.php.bak", "internal-api-keys.json", "staging", "old-admin",
	"phpmyadmin", "backup.tar.gz", "private-reports", "customer-list.csv",
}

// PerVisitor is how many trap paths each visitor sees in robots.txt.
const PerVisitor = 3

// Traps issues and classifies trap paths. It is safe for concurrent use.
type Traps struct {
	prefix  string
	current []byte
	all     [][]byte // current first, then previous (rotation)
}

// New returns a Traps under prefix (e.g. "/restricted"). previous may be nil;
// when set, paths signed with it are still recognised as Own.
func New(prefix string, secret, previous []byte) *Traps {
	t := &Traps{prefix: strings.TrimRight(prefix, "/"), current: secret, all: [][]byte{secret}}
	if len(previous) > 0 {
		t.all = append(t.all, previous)
	}
	return t
}

// Prefix returns the trap area prefix, without a trailing slash.
func (t *Traps) Prefix() string { return t.prefix }

func mac(secret []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return m.Sum(nil)
}

func token(secret []byte, key string) string {
	return hex.EncodeToString(mac(secret, "token", key))[:tokenLen]
}

// Paths returns the trap paths for a visitor key. They are stable for a key
// and secret, and unpredictable without the secret.
func (t *Traps) Paths(key string) []string {
	tok := token(t.current, key)
	seed := mac(t.current, "names", key)
	picked := make([]string, 0, PerVisitor)
	used := make(map[int]bool, PerVisitor)
	for i := 0; len(picked) < PerVisitor && i < len(seed); i++ {
		idx := int(seed[i]) % len(Names)
		if used[idx] {
			continue
		}
		used[idx] = true
		picked = append(picked, t.prefix+"/"+Names[idx]+"-"+tok)
	}
	return picked
}

// InArea reports whether p is inside the trap area.
func (t *Traps) InArea(p string) bool {
	p = clean(p)
	return p == t.prefix || strings.HasPrefix(p, t.prefix+"/")
}

// Classify tells whether p is a trap for the visitor with the given key.
func (t *Traps) Classify(key, p string) Kind {
	if !t.InArea(p) {
		return None
	}
	p = clean(p)
	i := strings.LastIndexByte(p, '-')
	if i < 0 {
		return Own // the bare trap area: only listed in robots.txt
	}
	tail := p[i+1:]
	for _, s := range t.all {
		if hmac.Equal([]byte(tail), []byte(token(s, key))) {
			return Own
		}
	}
	if isToken(tail) {
		return Shared
	}
	return Own
}

func isToken(s string) bool {
	if len(s) != tokenLen {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func clean(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}
