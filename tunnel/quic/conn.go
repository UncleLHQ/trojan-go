package quic

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/quic-go"
)

// conn wrap quic.Connection & quic.Stream as tunnel.Conn

type streamConn struct {
	quic.Connection
	quic.Stream

	lock      sync.Mutex
	closeOnce sync.Once
	closeErr  error

	laterClose func()
}

func (q *streamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.Stream.Write(p)
}

func (q *streamConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *streamConn) close() error {
	if q.laterClose != nil {
		defer time.AfterFunc(10*time.Second, q.laterClose)
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

var _ net.Conn = &streamConn{}

func newStreamConn(c quic.Connection, s quic.Stream, laterClose func()) *streamConn {
	return &streamConn{
		Connection: c,
		Stream:     s,

		laterClose: laterClose,
	}
}
