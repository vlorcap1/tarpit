package verdict

import (
	"slices"
	"testing"

	"github.com/vlorcap1/telarana/internal/goodbot"
	"github.com/vlorcap1/telarana/internal/store"
)

const threshold = 50

func TestEvaluate(t *testing.T) {
	browser := "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15"
	cases := []struct {
		name   string
		in     Input
		want   Verdict
		reason string
	}{
		{"plain browser", Input{UserAgent: browser}, Clean, ""},
		{"curl alone is not suspect", Input{UserAgent: "curl/8.4.0"}, Clean, "ua:tool"},
		{"fast curl is still not suspect", Input{UserAgent: "curl/8.4.0", Rate: 500, RateMax: 60}, Clean, "rate:high"},
		{"first trap hit", Input{UserAgent: browser, Visitor: store.Visitor{OwnHits: 1}}, Suspect, "trap:first-hit"},
		{"impostor crawler", Input{UserAgent: "Googlebot", Bot: goodbot.Impostor}, Suspect, "goodbot:impostor"},
		{"confirmed by repeat", Input{Visitor: store.Visitor{OwnHits: 2, Trapped: true}}, Trapped, "trap:repeat"},
		{"confirmed by shared", Input{Visitor: store.Visitor{SharedHits: 1, Trapped: true}}, Trapped, "trap:shared"},
		{"verified crawler wins over everything", Input{Bot: goodbot.Verified,
			Visitor: store.Visitor{OwnHits: 3, Trapped: true}}, VerifiedBot, "goodbot:verified"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(c.in, threshold)
			if r.Verdict != c.want {
				t.Errorf("verdict = %s (score %d, %v), want %s", r.Verdict, r.Score, r.Reasons, c.want)
			}
			if c.reason != "" && !slices.Contains(r.Reasons, c.reason) {
				t.Errorf("reasons %v missing %s", r.Reasons, c.reason)
			}
		})
	}
}

func TestSoftSignalsNeverTrap(t *testing.T) {
	r := Evaluate(Input{UserAgent: "", Rate: 1e6, RateMax: 1, Bot: goodbot.Impostor,
		Visitor: store.Visitor{OwnHits: 1}}, threshold)
	if r.Verdict == Trapped || r.Score > 99 {
		t.Errorf("soft signals reached %s with score %d", r.Verdict, r.Score)
	}
}
