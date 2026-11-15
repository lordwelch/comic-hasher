package log

import (
	"context"
	stdlog "log"

	"gitea.narnian.us/lordwelch/comic-hasher/log/diode"
)

type AsyncLogger struct {
	poller *diode.Poller
}

func NewAsyncLogger(ctx context.Context, size int, alerter diode.Alerter) *AsyncLogger {
	return &AsyncLogger{
		poller: diode.NewPoller(diode.NewManyToOne(size, alerter), diode.WithPollingContext(ctx)),
	}
}

func (a *AsyncLogger) Set(data Record) {
	a.poller.Set(diode.GenericDataType(&data))
}

func (a *AsyncLogger) TryNext() (Record, bool) {
	data, ok := a.poller.TryNext()
	if !ok {
		return Record{}, ok
	}

	return *(*Record)(data), true
}

func (a *AsyncLogger) Next() Record {
	data := a.poller.Next()
	if data == nil {
		return Record{}
	}
	return *(*Record)(data)
}

var Diode *AsyncLogger //= NewAsyncLogger(15, nil)

func (a *AsyncLogger) Drain() {
	r, ok := a.TryNext()
	for ok {
		stdlog.Println(format(LogFormat, r))

		r, ok = a.TryNext()
	}
}

func (a *AsyncLogger) Go() {
	d := Diode
	for {
		record := d.Next()
		if record.logger == Logger("") { // Empty logger is not allowed, an empty logger is sent on context cancel
			break
		}
		stdlog.Println(format(LogFormat, record))
		d.Drain()
	}
	Diode = nil
}
