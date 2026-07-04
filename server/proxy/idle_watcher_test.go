package proxy

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIdleWatcherClosesAfterTimeout(t *testing.T) {
	closed := make(chan struct{})
	w := startIdleWatcher(50*time.Millisecond, func() {
		close(closed)
	})
	defer w.stop()

	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("closeFn was not called after idle timeout")
	}
}

func TestIdleWatcherTouchPostponesClose(t *testing.T) {
	var closedFlag atomic.Bool
	w := startIdleWatcher(100*time.Millisecond, func() {
		closedFlag.Store(true)
	})
	defer w.stop()

	// keep the connection "active" well past the timeout
	for range 6 {
		time.Sleep(30 * time.Millisecond)
		w.touch()
	}
	require.False(t, closedFlag.Load(), "closeFn fired despite ongoing activity")

	// once activity stops, it should still close
	require.Eventually(t, closedFlag.Load, time.Second, 10*time.Millisecond)
}

func TestIdleWatcherStopPreventsClose(t *testing.T) {
	var closedFlag atomic.Bool
	w := startIdleWatcher(50*time.Millisecond, func() {
		closedFlag.Store(true)
	})
	w.stop()

	time.Sleep(150 * time.Millisecond)
	require.False(t, closedFlag.Load(), "closeFn fired after watcher was stopped")
}
