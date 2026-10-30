package log

import (
	"context"
	stdlog "log"
	"time"

	diodes "code.cloudfoundry.org/go-diodes"
)

type ManyToOne struct {
	poller *diodes.Poller
}

func NewManyToOne(ctx context.Context, size int, alerter diodes.Alerter) *ManyToOne {
	return &ManyToOne{
		poller: diodes.NewPoller(diodes.NewManyToOne(size, alerter), diodes.WithPollingContext(ctx)),
	}
}

func (d *ManyToOne) Set(data Record) {
	d.poller.Set(diodes.GenericDataType(&data))
}

func (d *ManyToOne) TryNext() (Record, bool) {
	data, ok := d.poller.TryNext()
	if !ok {
		return Record{}, ok
	}

	return *(*Record)(data), true
}

func (d *ManyToOne) Next() Record {
	data := d.poller.Next()
	return *(*Record)(data)
}

var Diode *ManyToOne //= NewManyToOne(15, nil)

type T struct { // TODO: what was this initially used for?
	token string
	value any
	index int
}

func drainLog(diode *ManyToOne) {
	r, ok := diode.TryNext()
	for ok {
		logStr := format(LogFormat, r)
		stdlog.Println(logStr)

		r, ok = diode.TryNext()
	}
}

func asyncLog(ctx context.Context, diode *ManyToOne) {
l:
	for {
		select {
		case <-time.Tick(time.Millisecond * 1):
			drainLog(diode)
		case <-ctx.Done():
			break l
		}
	}
	drainLog(&ManyToOne{diodes.NewPoller(diode.poller.Diode)})
}
