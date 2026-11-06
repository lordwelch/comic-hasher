package ch

import (
	"time"

	"gitea.narnian.us/lordwelch/comic-hasher/log"
)

type TimeLog struct {
	total time.Duration
	last  time.Time
}

func (t *TimeLog) ResetTime() {
	t.total = 0
	t.last = time.Now()
}

func (t *TimeLog) LogTime(msg string) {
	now := time.Now()
	diff := now.Sub(t.last)
	t.last = now
	t.total += diff
	log.Log(log.Trace, "total: %v, %s: %v\n", t.total, msg, diff)
}
