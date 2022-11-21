package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/tls/fingerprint"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

// Client is a tls client
type Client struct {
	serverAddress *tunnel.Address

	verify        bool
	sni           string
	ca            *x509.CertPool
	cipher        []uint16
	sessionTicket bool
	reuseSession  bool

	keyLogger io.WriteCloser

	ctx        context.Context
	cancel     context.CancelFunc
	nextProtos []string

	once sync.Once

	packetConn net.PacketConn
}

func (c *Client) Close() error {
	if c.keyLogger != nil {
		c.keyLogger.Close()
	}
	c.cancel()
	return nil
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (c *Client) DialConn(_ *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	quicSession, err := c.getQuicConn()
	if err != nil {
		return nil, common.NewError("quic failed to get connection").Base(err)
	}
	quicStream, err := quicSession.OpenStream()
	if err != nil {
		return nil, common.NewError("quic failed to open stream with remote server").Base(err)
	}
	return &transport.Conn{
		Conn: wrappedConn{
			quicSession,
			quicStream,
		},
	}, nil
}

func (c *Client) getQuicConn() (quicSession quic.Connection, err error) {
	// c.once.Do(func() {
	//c.packetConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	//})
	if err != nil {
		return nil, common.NewError("create packet conn failed").Base(err)
	}

	addrStr := c.serverAddress.String()
	// udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, common.NewError("ResolveUDPAddr failed").Base(err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify:     !c.verify,
		ServerName:             c.sni,
		RootCAs:                c.ca,
		KeyLogWriter:           c.keyLogger,
		CipherSuites:           c.cipher,
		SessionTicketsDisabled: !c.sessionTicket,
		NextProtos:             c.nextProtos,
	}

	quicSession, err = quic.DialAddr(addrStr, tlsConf, nil)
	if err != nil {
		return nil, common.NewError("quic failed to dial with remote server").Base(err)
	}
	return quicSession, nil
}

// NewClient creates a tls client
func NewClient(ctx context.Context, _ tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	if cfg.TLS.SNI == "" {
		cfg.TLS.SNI = cfg.RemoteHost
		log.Warn("tls sni is unspecified")
	}
	serverAddress := tunnel.NewAddressFromHostPort("udp", cfg.RemoteHost, cfg.RemotePort)

	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		serverAddress: serverAddress,

		verify:        cfg.TLS.Verify,
		sni:           cfg.TLS.SNI,
		cipher:        fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":")),
		sessionTicket: cfg.TLS.ReuseSession,
		nextProtos:    cfg.TLS.ALPN,

		ctx:    ctx,
		cancel: cancel,
	}

	log.Debug("quic client created")
	return client, nil
}
