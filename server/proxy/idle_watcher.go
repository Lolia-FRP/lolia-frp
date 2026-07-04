package proxy

import (
	"sync/atomic"
	"time"
)

// idleWatcher closes a proxied connection pair when no bytes have flowed in
// either direction for the configured timeout. Without it, endpoints that
// stay open at the TCP level but never send data again would pin the join
// goroutines and their transfer buffers forever.
type idleWatcher struct {
	lastActive atomic.Int64 // unix nano of the last byte transferred
	stopCh     chan struct{}
}

func startIdleWatcher(timeout time.Duration, closeFn func()) *idleWatcher {
	w := &idleWatcher{stopCh: make(chan struct{})}
	w.touch()

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-w.stopCh:
				return
			case <-timer.C:
				idle := time.Since(time.Unix(0, w.lastActive.Load()))
				if idle >= timeout {
					closeFn()
					return
				}
				timer.Reset(timeout - idle)
			}
		}
	}()
	return w
}

func (w *idleWatcher) touch() {
	w.lastActive.Store(time.Now().UnixNano())
}

func (w *idleWatcher) stop() {
	close(w.stopCh)
}
