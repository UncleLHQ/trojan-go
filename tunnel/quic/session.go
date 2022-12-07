package quic

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/quic-go"
)

type session struct {
	conn  quic.Connection
	mutex *sync.RWMutex

	dialFn func() (quic.Connection, error)

	updateTime      time.Time
	streamNum       int
	closedStreamNum int
}

func (s *session) IsAvailable() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.streamNum <= 16 && time.Now().Sub(s.updateTime) < 15*time.Second
}

func (s *session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.conn != nil && s.streamNum == s.closedStreamNum {
		err := s.conn.CloseWithError(0, "quic conn is closing")
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *session) newStream() (*streamConn, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.conn == nil {
		var err error
		s.conn, err = s.dialFn()
		if err != nil {
			return nil, err
		}
	}
	stream, err := s.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	s.streamNum++
	s.updateTime = time.Now()
	return newStreamConn(s.conn, stream, s.closeStream), nil
}

func (s *session) closeStream() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.closedStreamNum++
	if s.closedStreamNum == s.streamNum {
		defer time.AfterFunc(10*time.Second, func() {
			s.Close()
		})
	}
}

type sessionManager struct {
	ctx context.Context

	newSession func() (*session, error)
	session    *session

	mutex *sync.Mutex
}

func (p *sessionManager) getSession() (*session, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.session != nil && p.session.IsAvailable() {
		return p.session, nil
	}

	s, err := p.newSession()
	if err != nil {
		return nil, err
	}

	p.session = s
	return s, nil
}
