package verify

import "time"

// Throttle enforces a minimum delay between probes.
type Throttle struct {
	delay    time.Duration
	lastCall time.Time
}

// NewThrottle creates a throttle with the specified delay in milliseconds.
func NewThrottle(delayMs int) *Throttle {
	return &Throttle{
		delay: time.Duration(delayMs) * time.Millisecond,
	}
}

// Wait blocks until enough time has passed since the last call.
func (t *Throttle) Wait() {
	if !t.lastCall.IsZero() {
		elapsed := time.Since(t.lastCall)
		if elapsed < t.delay {
			time.Sleep(t.delay - elapsed)
		}
	}
	t.lastCall = time.Now()
}
