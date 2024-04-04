package server

import (
	"context"

	"github.com/p4gefau1t/trojan-go/tunnel/quic"

	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel/freedom"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

const Name = "QUIC_SERVER"

func init() {
	proxy.RegisterProxyCreator(Name, buildProxy)
}

func buildProxy(ctx context.Context) (*proxy.Proxy, error) {
	ctx, cancel := context.WithCancel(ctx)
	quicServer, err := quic.NewServer(ctx, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	clientStack := []string{freedom.Name}

	root := &proxy.Node{
		Name:       quic.Name,
		Next:       make(map[string]*proxy.Node),
		IsEndpoint: false,
		Context:    ctx,
		Server:     quicServer,
	}

	trojanSubTree := root
	trojanSubTree.BuildNext(trojan.Name).IsEndpoint = true

	serverList := proxy.FindAllEndpoints(root)
	clientList, err := proxy.CreateClientStack(ctx, clientStack)
	if err != nil {
		cancel()
		return nil, err
	}
	return proxy.NewProxy(ctx, cancel, serverList, clientList), nil
}
