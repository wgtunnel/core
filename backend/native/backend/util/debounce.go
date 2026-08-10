package util

import "time"

// Debouncer collapses bursts of events into a single callback after a quiet period.
// Typical use inside a select loop:
//
//	deb := util.NewDebouncer(200 * time.Millisecond)
//	for {
//	    select {
//	    case <-eventCh:
//	        deb.Hit()
//	    case <-deb.C:
//	        deb.Fired()
//	        doWork()
//	    case <-stopCh:
//	        deb.Stop()
//	        return
//	    }
//	}
type Debouncer struct {
	interval time.Duration
	timer    *time.Timer
	C        <-chan time.Time
}

func NewDebouncer(interval time.Duration) *Debouncer {
	return &Debouncer{interval: interval}
}

// Hit arms or resets the timer.
func (d *Debouncer) Hit() {
	if d.timer == nil {
		d.timer = time.NewTimer(d.interval)
		d.C = d.timer.C
		return
	}
	if !d.timer.Stop() {
		// Timer already fired; drain so Reset is safe.
		select {
		case <-d.timer.C:
		default:
		}
	}
	d.timer.Reset(d.interval)
	d.C = d.timer.C
}

// Fired clears timer state after a successful reception from C.
func (d *Debouncer) Fired() {
	d.timer = nil
	d.C = nil
}

// Stop cancels any pending timer.
func (d *Debouncer) Stop() {
	if d.timer == nil {
		return
	}
	if !d.timer.Stop() {
		select {
		case <-d.timer.C:
		default:
		}
	}
	d.timer = nil
	d.C = nil
}
