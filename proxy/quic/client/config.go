package client

import "github.com/p4gefau1t/trojan-go/config"

type Config struct{}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(Config)
	})
}
