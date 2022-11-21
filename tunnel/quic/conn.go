package quic

import "github.com/lucas-clemente/quic-go"

// conn wrap quic.Connection & quic.Stream as tunnel.Conn
type wrappedConn struct {
	quic.Connection
	quic.Stream
}
