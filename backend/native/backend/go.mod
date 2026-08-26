module github.com/wgtunnel/backend

go 1.27.0

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.0.20260805
	github.com/artem-russkikh/wireproxy-awg v1.0.12
	github.com/godbus/dbus/v5 v5.2.2
	github.com/google/nftables v0.3.0
	github.com/mdlayher/wifi v0.9.0
	github.com/miekg/dns v1.1.72
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
	github.com/vishvananda/netlink v1.3.1
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard/windows v1.0.1
)

require (
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/MakeNowJust/heredoc/v2 v2.0.1 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/things-go/go-socks5 v0.1.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/exp/typeparams v0.0.0-20240314144324-c7f7c6466f7f // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8 // indirect
	honnef.co/go/tools v0.7.0 // indirect
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => github.com/wgtunnel/amneziawg-go/v3 v3.0.0-20260826061744-01780d1dd3b8

replace github.com/artem-russkikh/wireproxy-awg => github.com/wgtunnel/wireproxy-awg v0.0.0-20260826063852-a3a8a1aff15f
