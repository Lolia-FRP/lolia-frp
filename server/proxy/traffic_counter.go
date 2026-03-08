package proxy

import "io"

type countingReadWriteCloser struct {
	io.ReadWriteCloser
	onRead  func(int64)
	onWrite func(int64)
}

func wrapCountingReadWriteCloser(rwc io.ReadWriteCloser, onRead, onWrite func(int64)) io.ReadWriteCloser {
	if onRead == nil && onWrite == nil {
		return rwc
	}
	return &countingReadWriteCloser{
		ReadWriteCloser: rwc,
		onRead:          onRead,
		onWrite:         onWrite,
	}
}

func (c *countingReadWriteCloser) Read(p []byte) (n int, err error) {
	n, err = c.ReadWriteCloser.Read(p)
	if n > 0 && c.onRead != nil {
		c.onRead(int64(n))
	}
	return
}

func (c *countingReadWriteCloser) Write(p []byte) (n int, err error) {
	n, err = c.ReadWriteCloser.Write(p)
	if n > 0 && c.onWrite != nil {
		c.onWrite(int64(n))
	}
	return
}
