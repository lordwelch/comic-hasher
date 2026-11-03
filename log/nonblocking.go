package log

import (
	"context"
	stdlog "log"
	"time"

	diodes "code.cloudfoundry.org/go-diodes"
)

type ManyToOne struct {
	poller *Poller
}

func NewManyToOne(ctx context.Context, size int, alerter diodes.Alerter) *ManyToOne {
	return &ManyToOne{
		poller: NewPoller(diodes.NewManyToOne(size, alerter), WithPollingContext(ctx)),
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
	if data == nil {
		return Record{}
	}
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
		stdlog.Println(format(LogFormat, r))

		r, ok = diode.TryNext()
	}
}

func asyncLog(diode *ManyToOne) {
	for {
		record := diode.Next()
		if record.logger == Logger("") { // Empty logger is not allowed
			break
		}
		stdlog.Println(format(LogFormat, record))
		drainLog(diode)
	}
	// Context is canceled we need a new poller that isn't canceled to drain the logger
	drainLog(&ManyToOne{NewPoller(diode.poller.Diode)})
}

// Poller will poll a diode until a value is available.
type Poller struct {
	diodes.Diode
	interval time.Duration
	ctx      context.Context
}

// PollerConfigOption can be used to setup the poller.
type PollerConfigOption func(*Poller)

// WithPollingInterval sets the interval at which the diode is queried
// for new data. The default is 10ms.
func WithPollingInterval(interval time.Duration) PollerConfigOption {
	return PollerConfigOption(func(c *Poller) {
		c.interval = interval
	})
}

// WithPollingContext sets the context to cancel any retrieval (Next()). It
// will not change any results for adding data (Set()). Default is
// context.Background().
func WithPollingContext(ctx context.Context) PollerConfigOption {
	return PollerConfigOption(func(c *Poller) {
		c.ctx = ctx
	})
}

// NewPoller returns a new Poller that wraps the given diode.
func NewPoller(d diodes.Diode, opts ...PollerConfigOption) *Poller {
	p := &Poller{
		Diode:    d,
		interval: 10 * time.Millisecond,
		ctx:      context.Background(),
	}

	for _, o := range opts {
		o(p)
	}

	return p
}

// Next polls the diode until data is available or until the context is done.
// If the context is done, then nil will be returned.
func (p *Poller) Next() diodes.GenericDataType {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		data, ok := p.Diode.TryNext() // nolint:staticcheck
		if !ok {
			select {
			case <-ticker.C:
			case <-p.ctx.Done():
				return nil
			}
			continue
		}
		return data
	}
}

func (p *Poller) isDone() bool {
	select {
	case <-p.ctx.Done():
		return true
	default:
		return false
	}
}
