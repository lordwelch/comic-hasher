package ch

import (
	"fmt"
	"time"
)

type timeLog struct {
	total time.Duration
	last  time.Time
}

func (t *timeLog) resetTime() {
	t.total = 0
	t.last = time.Now()
}

func (t *timeLog) logTime(log string) {
	now := time.Now()
	diff := now.Sub(t.last)
	t.last = now
	t.total += diff
	fmt.Printf("total: %v, %s: %v\n", t.total, log, diff)
}
