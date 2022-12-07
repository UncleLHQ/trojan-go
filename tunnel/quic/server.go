package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/Dreamacro/clash/transport/tuic"
	"github.com/metacubex/quic-go"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/tls/fingerprint"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
)

// Server is a tls server
type Server struct {
	listener quic.Listener

	connChan chan tunnel.Conn

	ctx    context.Context
	cancel context.CancelFunc

	nextHTTP      int32
	portOverrider map[string]int
}

func (s *Server) Close() error {
	s.cancel()
	return nil
}

func (s *Server) acceptStreamLoop(conn quic.Connection) {
	log.Info("quic connection from", conn.RemoteAddr())
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Error(common.NewError("quic stream accept error").Base(err))
				time.Sleep(time.Millisecond * 100)
			}
			return
		}
		log.Info("quic stream from", conn.RemoteAddr(), ",stream ID :", stream.StreamID())
		go func(stream quic.Stream) {
			s.connChan <- &transport.Conn{
				newStreamConn(conn, stream, nil),
			}
		}(stream)
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Error(common.NewError("quic conn accept error").Base(err))
				time.Sleep(time.Millisecond * 100)
			}
			return
		}
		tuic.SetCongestionController(conn, "bbr")
		go s.acceptStreamLoop(conn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	// trojan overlay
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

// NewServer creates a tls layer server
func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	tlsConfig, err := generateTLSConfig(*cfg)
	if err != nil {
		return nil, common.NewError("gen tls config err").Base(err)
	}

	listenAddress := tunnel.NewAddressFromHostPort("udp", cfg.LocalHost, cfg.LocalPort)
	listener, err := quic.ListenAddr(listenAddress.String(), tlsConfig, nil)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		listener: listener,

		connChan: make(chan tunnel.Conn, 32),

		ctx:    ctx,
		cancel: cancel,
	}

	go server.acceptLoop()

	log.Debug("tls server created")
	return server, nil
}

func generateTLSConfig(cfg Config) (tlsConfig *tls.Config, err error) {
	keyPair, err := loadKeyPair(cfg.TLS.KeyPath, cfg.TLS.CertPath, cfg.TLS.KeyPassword)
	if err != nil {
		return nil, common.NewError("tls failed to load key pair")
	}

	var keyLogger io.WriteCloser
	if cfg.TLS.KeyLogPath != "" {
		log.Warn("tls key logging activated. USE OF KEY LOGGING COMPROMISES SECURITY. IT SHOULD ONLY BE USED FOR DEBUGGING.")
		file, err := os.OpenFile(cfg.TLS.KeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, common.NewError("failed to open key log file").Base(err)
		}
		keyLogger = file
	}

	var cipherSuite []uint16
	if len(cfg.TLS.Cipher) != 0 {
		cipherSuite = fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":"))
	}

	tlsConfig = &tls.Config{
		CipherSuites: cipherSuite,

		SessionTicketsDisabled: !cfg.TLS.ReuseSession,
		NextProtos:             cfg.TLS.ALPN,
		KeyLogWriter:           keyLogger,

		Certificates: []tls.Certificate{*keyPair},
	}

	return tlsConfig, nil
}

func loadKeyPair(keyPath string, certPath string, password string) (*tls.Certificate, error) {
	if password != "" {
		keyFile, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, common.NewError("failed to load key file").Base(err)
		}
		keyBlock, _ := pem.Decode(keyFile)
		if keyBlock == nil {
			return nil, common.NewError("failed to decode key file").Base(err)
		}
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err == nil {
			return nil, common.NewError("failed to decrypt key").Base(err)
		}

		certFile, err := ioutil.ReadFile(certPath)
		certBlock, _ := pem.Decode(certFile)
		if certBlock == nil {
			return nil, common.NewError("failed to decode cert file").Base(err)
		}

		keyPair, err := tls.X509KeyPair(certBlock.Bytes, decryptedKey)
		if err != nil {
			return nil, err
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, common.NewError("failed to parse leaf certificate").Base(err)
		}

		return &keyPair, nil
	}
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, common.NewError("failed to load key pair").Base(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, common.NewError("failed to parse leaf certificate").Base(err)
	}
	return &keyPair, nil
}
