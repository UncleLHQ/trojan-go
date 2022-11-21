//go:build server || full || mini
// +build server full mini

package build

import (
	_ "github.com/p4gefau1t/trojan-go/proxy/server"

	_ "github.com/p4gefau1t/trojan-go/proxy/quic/server"
)
