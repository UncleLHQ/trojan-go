package client

import (
	"context"

	"github.com/p4gefau1t/trojan-go/tunnel/quic"

	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/adapter"
	"github.com/p4gefau1t/trojan-go/tunnel/http"
	"github.com/p4gefau1t/trojan-go/tunnel/socks"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

const Name = "QUIC_CLIENT"

// GenerateClientTree generate general outbound protocol stack
func GenerateClientTree() []string {
	clientStack := []string{quic.Name, trojan.Name}

	return clientStack
}

func init() {
	proxy.RegisterProxyCreator(Name, buildProxy)
}

func buildProxy(ctx context.Context) (*proxy.Proxy, error) {
	adapterServer, err := adapter.NewServer(ctx, nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)

	root := &proxy.Node{
		Name:       adapter.Name,
		Next:       make(map[string]*proxy.Node),
		IsEndpoint: false,
		Context:    ctx,
		Server:     adapterServer,
	}

	root.BuildNext(http.Name).IsEndpoint = true
	root.BuildNext(socks.Name).IsEndpoint = true

	clientStack := GenerateClientTree()
	c, err := proxy.CreateClientStack(ctx, clientStack)
	if err != nil {
		cancel()
		return nil, err
	}
	s := proxy.FindAllEndpoints(root)
	return proxy.NewProxy(ctx, cancel, s, c), nil
}
