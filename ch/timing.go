package ch

import (
	"time"

	"gitea.narnian.us/lordwelch/comic-hasher/log"
)

type TimeLog struct {
	total  time.Duration
	last   time.Time
	Logger log.Logger
}

func (t *TimeLog) ResetTime() {
	t.total = 0
	t.last = time.Now()
	if t.Logger == "" {
		t.Logger = log.NewLogger("")
	}
}

func (t *TimeLog) LogTime(msg string) {
	now := time.Now()
	diff := now.Sub(t.last)
	t.last = now
	t.total += diff
	t.Logger.Log(log.Trace, "total: %v, %s: %v", t.total, msg, diff)
}
