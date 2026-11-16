// Package verdict turns what Telaraña knows about a visitor into a verdict.
//
// The rules are deliberately simple and explainable: every point of score
// comes with a reason that is reported to the proxy and in the logs.
package verdict

import (
	"strings"

	"github.com/vlorcap1/telarana/internal/goodbot"
	"github.com/vlorcap1/telarana/internal/store"
)

// Verdict is the outcome reported to the reverse proxy.
type Verdict string

const (
	Clean       Verdict = "clean"
	VerifiedBot Verdict = "verified-bot"
	Suspect     Verdict = "suspect"
	Trapped     Verdict = "trapped"
)

// Score contributions. Only traps can reach Trapped; no combination of the
// softer signals can.
const (
	scoreFirstTrapHit = 60
	scoreImpostor     = 50
	scoreToolUA       = 15
	maxRateScore      = 30
)

// toolAgents are User-Agent fragments of HTTP libraries and CLI tools. Many
// are legitimate (monitoring, scripts), so on their own they never make a
// visitor suspect.
var toolAgents = []string{
	"python-requests", "python-urllib", "aiohttp", "httpx", "curl/", "wget/",
	"go-http-client", "scrapy", "okhttp", "java/", "libwww-perl", "node-fetch", "axios/",
}

// Input is everything the rules look at.
type Input struct {
	Visitor   store.Visitor
	Rate      int // requests from this address in the window
	RateMax   int
	UserAgent string
	Bot       goodbot.Status
}

// Result is a verdict with its score (0-100) and the reasons behind it.
type Result struct {
	Verdict Verdict
	Score   int
	Reasons []string
}

// Evaluate applies the rules. suspectScore is the threshold for Suspect.
func Evaluate(in Input, suspectScore int) Result {
	// A DNS-verified search engine is never penalised, even if it somehow
	// requested a trap: blocking it would hurt the site far more than it helps.
	if in.Bot == goodbot.Verified {
		return Result{Verdict: VerifiedBot, Score: 0, Reasons: []string{"goodbot:verified"}}
	}
	if in.Visitor.Trapped {
		reason := "trap:repeat"
		if in.Visitor.SharedHits > 0 {
			reason = "trap:shared"
		}
		return Result{Verdict: Trapped, Score: 100, Reasons: []string{reason}}
	}

	var r Result
	add := func(points int, reason string) {
		r.Score += points
		r.Reasons = append(r.Reasons, reason)
	}
	if in.Visitor.OwnHits > 0 {
		add(scoreFirstTrapHit, "trap:first-hit")
	}
	if in.Bot == goodbot.Impostor {
		add(scoreImpostor, "goodbot:impostor")
	}
	if in.RateMax > 0 && in.Rate > in.RateMax {
		add(min(maxRateScore, in.Rate-in.RateMax), "rate:high")
	}
	if isToolUA(in.UserAgent) {
		add(scoreToolUA, "ua:tool")
	}
	if r.Score > 99 {
		r.Score = 99 // 100 is reserved for confirmed traps
	}
	r.Verdict = Clean
	if r.Score >= suspectScore {
		r.Verdict = Suspect
	}
	return r
}

func isToolUA(ua string) bool {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" || ua == "-" {
		return true
	}
	for _, t := range toolAgents {
		if strings.Contains(ua, t) {
			return true
		}
	}
	return false
}
