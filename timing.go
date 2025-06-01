package ch

import (
	"fmt"
	"time"
)

type TimeLog struct {
	total time.Duration
	last  time.Time
}

func (t *TimeLog) ResetTime() {
	t.total = 0
	t.last = time.Now()
}

func (t *TimeLog) LogTime(log string) {
	now := time.Now()
	diff := now.Sub(t.last)
	t.last = now
	t.total += diff
	fmt.Printf("total: %v, %s: %v\n", t.total, log, diff)
}
