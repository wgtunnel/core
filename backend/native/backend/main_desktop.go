//go:build !android

package main

import (
	_ "github.com/wgtunnel/backend/bootstrap"
	_ "github.com/wgtunnel/backend/dns/transport/local"
	_ "github.com/wgtunnel/backend/handle"
	_ "github.com/wgtunnel/backend/jni"
	_ "github.com/wgtunnel/backend/killswitch"
	_ "github.com/wgtunnel/backend/network"
	_ "github.com/wgtunnel/backend/proxy"
	_ "github.com/wgtunnel/backend/statusnotify"
	_ "github.com/wgtunnel/backend/vpn"
)

func main() {}
