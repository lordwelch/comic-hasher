package ch

import (
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"
)

type TimeLog struct {
	total time.Duration
	last  time.Time
	msgs []Message
	mu sync.Mutex
}

type Message struct {
	log string
	total time.Duration
	diff time.Duration
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
	t.mu.Lock()
	defer t.mu.Unlock()
	t.msgs = append(t.msgs, Message{log,t.total,diff})
}



func NewTimeLog() *TimeLog {
	t := &TimeLog{
	}
	go func() {
		for {
			<-time.After(time.Second)
			t.mu.Lock()
			msgs := slices.Clone(t.msgs)
			t.msgs = t.msgs[0:0]
			t.mu.Unlock()
			if len(msgs) == 0 {
				continue
			}
			fmt.Printf("Number of goroutines: %d\n", runtime.NumGoroutine())
			fmt.Printf("Number of messages: %d\n", len(msgs))
			for _,m := range msgs {
				fmt.Printf("total: %v, %s: %v\n", m.total, m.log, m.diff)
			}
		}
	}()
	return t
}
