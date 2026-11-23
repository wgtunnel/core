// Copyright (c) 2026 Zane Schepke / WG Tunnel

//go:build darwin && cgo

package osfirewall

/*
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

// The macOS SDK does not ship net/pfvar.h. These are the LP64 user-space
// layouts of the XNU structs the ioctls below take. Fields this file never
// reads are kept as opaque bytes. The asserts pin every size and offset used
// to the values in the bindgen layout tests of mullvad/pfctl-rs, so a layout
// mistake fails the build instead of corrupting a kernel request.

#define WGT_PF_PASS 0
#define WGT_PF_OUT 2
#define WGT_PF_OP_EQ 2
#define WGT_PF_GET_NONE 0

struct wgt_pf_addr {
	union {
		struct in_addr v4;
		struct in6_addr v6;
		uint8_t addr8[16];
		uint32_t addr32[4];
	} pfa;
};

struct wgt_pf_addr_wrap {
	union {
		struct {
			struct wgt_pf_addr addr;
			struct wgt_pf_addr mask;
		} a;
		char ifname[IFNAMSIZ];
		char tblname[32];
	} v;
	union {
		uint64_t ptr;
		int cnt;
	} p;
	uint8_t type;
	uint8_t iflags;
};

struct wgt_pf_port_range {
	uint16_t port[2];
	uint8_t op;
};

union wgt_pf_rule_xport {
	struct wgt_pf_port_range range;
	uint16_t call_id;
	uint32_t spi;
};

union wgt_pf_state_xport {
	uint16_t port;
	uint16_t call_id;
	uint32_t spi;
};

struct wgt_pf_rule {
	uint8_t _head[688];
	uint64_t ticket;
	char owner[64];
	uint8_t _mid[1004 - 760];
	uint8_t action;
	uint8_t _tail[1040 - 1005];
};

struct wgt_pfioc_rule {
	uint32_t action;
	uint32_t ticket;
	uint32_t pool_ticket;
	uint32_t nr;
	char anchor[MAXPATHLEN];
	char anchor_call[MAXPATHLEN];
	struct wgt_pf_rule rule;
};

struct wgt_pfsync_state_host {
	struct wgt_pf_addr addr;
	union wgt_pf_state_xport xport;
	uint16_t pad[2];
} __attribute__((packed));

struct wgt_pfsync_state {
	uint32_t id[2];
	char ifname[IFNAMSIZ];
	struct wgt_pfsync_state_host lan;
	struct wgt_pfsync_state_host gwy;
	struct wgt_pfsync_state_host ext_lan;
	struct wgt_pfsync_state_host ext_gwy;
	uint8_t _peers_to_tag[282 - 120];
	uint8_t af_lan;
	uint8_t af_gwy;
	uint8_t proto;
	uint8_t direction;
	uint8_t _log_to_updates[291 - 286];
	uint8_t proto_variant;
	uint8_t _pad;
	uint32_t flowhash;
} __attribute__((packed));

struct wgt_pfioc_states {
	int ps_len;
	union {
		char *buf;
		struct wgt_pfsync_state *states;
	} ps_u;
};

struct wgt_pfioc_state_addr_kill {
	struct wgt_pf_addr_wrap addr;
	uint8_t reserved_[3];
	uint8_t neg;
	union wgt_pf_rule_xport xport;
};

struct wgt_pfioc_state_kill {
	uint8_t psk_af;
	uint8_t psk_proto;
	uint8_t psk_proto_variant;
	uint8_t _pad;
	struct wgt_pfioc_state_addr_kill psk_src;
	struct wgt_pfioc_state_addr_kill psk_dst;
	char psk_ifname[IFNAMSIZ];
	char psk_ownername[64];
};

#define WGT_ASSERT_SIZE(t, n) _Static_assert(sizeof(t) == (n), "sizeof " #t)
#define WGT_ASSERT_OFF(t, f, n) _Static_assert(offsetof(t, f) == (n), "offsetof " #t "." #f)

WGT_ASSERT_SIZE(struct wgt_pf_addr, 16);
WGT_ASSERT_SIZE(struct wgt_pf_addr_wrap, 48);
WGT_ASSERT_OFF(struct wgt_pf_addr_wrap, p, 32);
WGT_ASSERT_OFF(struct wgt_pf_addr_wrap, type, 40);
WGT_ASSERT_SIZE(struct wgt_pf_port_range, 6);
WGT_ASSERT_SIZE(union wgt_pf_rule_xport, 8);
WGT_ASSERT_SIZE(union wgt_pf_state_xport, 4);
WGT_ASSERT_SIZE(struct wgt_pf_rule, 1040);
WGT_ASSERT_OFF(struct wgt_pf_rule, ticket, 688);
WGT_ASSERT_OFF(struct wgt_pf_rule, owner, 696);
WGT_ASSERT_OFF(struct wgt_pf_rule, action, 1004);
WGT_ASSERT_SIZE(struct wgt_pfioc_rule, 3104);
WGT_ASSERT_OFF(struct wgt_pfioc_rule, nr, 12);
WGT_ASSERT_OFF(struct wgt_pfioc_rule, anchor, 16);
WGT_ASSERT_OFF(struct wgt_pfioc_rule, anchor_call, 1040);
WGT_ASSERT_OFF(struct wgt_pfioc_rule, rule, 2064);
WGT_ASSERT_SIZE(struct wgt_pfsync_state_host, 24);
WGT_ASSERT_OFF(struct wgt_pfsync_state_host, xport, 16);
WGT_ASSERT_SIZE(struct wgt_pfsync_state, 297);
WGT_ASSERT_OFF(struct wgt_pfsync_state, ifname, 8);
WGT_ASSERT_OFF(struct wgt_pfsync_state, lan, 24);
WGT_ASSERT_OFF(struct wgt_pfsync_state, ext_lan, 72);
WGT_ASSERT_OFF(struct wgt_pfsync_state, af_lan, 282);
WGT_ASSERT_OFF(struct wgt_pfsync_state, proto, 284);
WGT_ASSERT_OFF(struct wgt_pfsync_state, direction, 285);
WGT_ASSERT_OFF(struct wgt_pfsync_state, proto_variant, 291);
WGT_ASSERT_OFF(struct wgt_pfsync_state, flowhash, 293);
WGT_ASSERT_SIZE(struct wgt_pfioc_states, 16);
WGT_ASSERT_OFF(struct wgt_pfioc_states, ps_u, 8);
WGT_ASSERT_SIZE(struct wgt_pfioc_state_addr_kill, 64);
WGT_ASSERT_OFF(struct wgt_pfioc_state_addr_kill, neg, 51);
WGT_ASSERT_OFF(struct wgt_pfioc_state_addr_kill, xport, 52);
WGT_ASSERT_SIZE(struct wgt_pfioc_state_kill, 216);
WGT_ASSERT_OFF(struct wgt_pfioc_state_kill, psk_src, 8);
WGT_ASSERT_OFF(struct wgt_pfioc_state_kill, psk_dst, 72);
WGT_ASSERT_OFF(struct wgt_pfioc_state_kill, psk_ifname, 136);
WGT_ASSERT_OFF(struct wgt_pfioc_state_kill, psk_ownername, 152);

// The ioctl numbers encode the struct size, so they only match the kernel
// when the asserts above hold.
#define WGT_DIOCGETRULES _IOWR('D', 6, struct wgt_pfioc_rule)
#define WGT_DIOCGETRULE _IOWR('D', 7, struct wgt_pfioc_rule)
#define WGT_DIOCGETSTATES _IOWR('D', 25, struct wgt_pfioc_states)
#define WGT_DIOCINSERTRULE _IOWR('D', 27, struct wgt_pfioc_rule)
#define WGT_DIOCDELETERULE _IOWR('D', 28, struct wgt_pfioc_rule)
#define WGT_DIOCKILLSTATES _IOWR('D', 41, struct wgt_pfioc_state_kill)

#define WGT_ANCHOR_SKIPPED 1

struct pf_snap {
	int fd;
	struct wgt_pfsync_state *raw;
	int n;
};

static int pf_open(void) {
	return open("/dev/pf", O_RDWR);
}

// The kernel reports an absolute anchor call with a leading slash.
static int anchor_call_is(const char *call, const char *name) {
	if (call[0] == '/') {
		call++;
	}
	return strncmp(call, name, MAXPATHLEN) == 0;
}

// find_anchor_rule leaves pr holding the main-ruleset rule that calls name.
// Returns 1 when found, 0 when absent, or -errno.
static int find_anchor_rule(int fd, const char *name, struct wgt_pfioc_rule *pr) {
	memset(pr, 0, sizeof *pr);
	pr->rule.action = WGT_PF_PASS;
	if (ioctl(fd, WGT_DIOCGETRULES, pr) < 0) {
		return -errno;
	}
	uint32_t nr = pr->nr;
	uint32_t ticket = pr->ticket;
	for (uint32_t i = 0; i < nr; i++) {
		memset(pr, 0, sizeof *pr);
		pr->rule.action = WGT_PF_PASS;
		pr->action = WGT_PF_GET_NONE;
		pr->ticket = ticket;
		pr->nr = i;
		if (ioctl(fd, WGT_DIOCGETRULE, pr) < 0) {
			return -errno;
		}
		if (anchor_call_is(pr->anchor_call, name)) {
			return 1;
		}
	}
	return 0;
}

int wgtunnel_pf_has_anchor(const char *name) {
	int fd = pf_open();
	if (fd < 0) {
		return -errno;
	}
	struct wgt_pfioc_rule pr;
	int rc = find_anchor_rule(fd, name, &pr);
	close(fd);
	return rc;
}

int wgtunnel_pf_add_anchor(const char *name) {
	int fd = pf_open();
	if (fd < 0) {
		return -errno;
	}
	struct wgt_pfioc_rule pr;
	memset(&pr, 0, sizeof pr);
	if (strlcpy(pr.anchor_call, name, sizeof pr.anchor_call) >= sizeof pr.anchor_call) {
		close(fd);
		return -ENAMETOOLONG;
	}
	pr.rule.action = WGT_PF_PASS;
	if (ioctl(fd, WGT_DIOCINSERTRULE, &pr) < 0) {
		int err = errno;
		close(fd);
		return err == EEXIST ? 0 : -err;
	}
	close(fd);
	return 0;
}

// wgtunnel_pf_remove_anchor deletes the call by its ticket. A call with no
// ticket came from a loaded pf.conf. DIOCDELETERULE treats ticket 0 as
// "delete every rule of this owner", and the owner is empty, so that call is
// left in place and WGT_ANCHOR_SKIPPED is returned.
int wgtunnel_pf_remove_anchor(const char *name) {
	int fd = pf_open();
	if (fd < 0) {
		return -errno;
	}
	struct wgt_pfioc_rule pr;
	int rc = find_anchor_rule(fd, name, &pr);
	if (rc <= 0) {
		close(fd);
		return rc;
	}
	if (pr.rule.ticket == 0) {
		close(fd);
		return WGT_ANCHOR_SKIPPED;
	}
	if (ioctl(fd, WGT_DIOCDELETERULE, &pr) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}
	close(fd);
	return 0;
}

static int copy_host(uint8_t af, const void *addr, unsigned char out[16]) {
	memset(out, 0, 16);
	if (af == AF_INET) {
		memcpy(out, addr, 4);
		return 4;
	}
	if (af == AF_INET6) {
		memcpy(out, addr, 16);
		return 16;
	}
	return 0;
}

struct pf_snap *wgtunnel_pf_snap_open(int *errn) {
	struct pf_snap *s = calloc(1, sizeof *s);
	if (s == NULL) {
		*errn = ENOMEM;
		return NULL;
	}
	s->fd = pf_open();
	if (s->fd < 0) {
		*errn = errno;
		free(s);
		return NULL;
	}
	struct wgt_pfioc_states ps;
	memset(&ps, 0, sizeof ps);
	if (ioctl(s->fd, WGT_DIOCGETSTATES, &ps) < 0) {
		*errn = errno;
		close(s->fd);
		free(s);
		return NULL;
	}
	if (ps.ps_len <= 0) {
		return s;
	}
	// Room for states created between the size query and the copy.
	int need = ps.ps_len + 64 * (int)sizeof(struct wgt_pfsync_state);
	s->raw = malloc((size_t)need);
	if (s->raw == NULL) {
		*errn = ENOMEM;
		close(s->fd);
		free(s);
		return NULL;
	}
	memset(&ps, 0, sizeof ps);
	ps.ps_len = need;
	ps.ps_u.states = s->raw;
	if (ioctl(s->fd, WGT_DIOCGETSTATES, &ps) < 0) {
		*errn = errno;
		free(s->raw);
		close(s->fd);
		free(s);
		return NULL;
	}
	if (ps.ps_len > need) {
		*errn = EAGAIN;
		free(s->raw);
		close(s->fd);
		free(s);
		return NULL;
	}
	s->n = ps.ps_len / (int)sizeof(struct wgt_pfsync_state);
	return s;
}

void wgtunnel_pf_snap_close(struct pf_snap *s) {
	if (s == NULL) {
		return;
	}
	free(s->raw);
	if (s->fd >= 0) {
		close(s->fd);
	}
	free(s);
}

int wgtunnel_pf_snap_count(struct pf_snap *s) {
	return s == NULL ? 0 : s->n;
}

// lan is the local side and ext_lan the remote side in both directions.
// Ports are returned in host byte order.
int wgtunnel_pf_snap_view(struct pf_snap *s, int i, char *ifname, int ifname_len,
		int *proto, unsigned char local[16], int *local_len, int *local_port,
		unsigned char remote[16], int *remote_len, int *remote_port) {
	if (s == NULL || i < 0 || i >= s->n || ifname_len <= 0) {
		return -EINVAL;
	}
	const struct wgt_pfsync_state *st = &s->raw[i];
	memset(ifname, 0, (size_t)ifname_len);
	size_t n = sizeof st->ifname;
	if ((size_t)ifname_len - 1 < n) {
		n = (size_t)ifname_len - 1;
	}
	memcpy(ifname, st->ifname, n);
	*proto = st->proto;
	*local_len = copy_host(st->af_lan, &st->lan.addr, local);
	*local_port = ntohs(st->lan.xport.port);
	*remote_len = copy_host(st->af_lan, &st->ext_lan.addr, remote);
	*remote_port = ntohs(st->ext_lan.xport.port);
	return 0;
}

static void set_kill_host(struct wgt_pfioc_state_addr_kill *k,
		const struct wgt_pfsync_state_host *h, uint8_t proto) {
	memcpy(&k->addr.v.a.addr, &h->addr, sizeof h->addr);
	memset(&k->addr.v.a.mask, 0xff, sizeof k->addr.v.a.mask);
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		k->xport.range.op = WGT_PF_OP_EQ;
		k->xport.range.port[0] = h->xport.port;
		break;
	default:
		// ESP compares spi and PPTP GRE compares call_id. Both sit at the
		// start of the state xport.
		memcpy(&k->xport, &h->xport, sizeof h->xport);
		break;
	}
}

// wgtunnel_pf_snap_kill kills the one state at index i. The key is the full
// address and port of both sides, so it matches only that flow. The kernel
// compares psk_src and psk_dst against lan and ext_lan swapped by direction.
int wgtunnel_pf_snap_kill(struct pf_snap *s, int i) {
	if (s == NULL || i < 0 || i >= s->n) {
		return -EINVAL;
	}
	const struct wgt_pfsync_state *st = &s->raw[i];
	if (st->af_lan != AF_INET && st->af_lan != AF_INET6) {
		return 0;
	}
	const struct wgt_pfsync_state_host *src = &st->ext_lan;
	const struct wgt_pfsync_state_host *dst = &st->lan;
	if (st->direction == WGT_PF_OUT) {
		src = &st->lan;
		dst = &st->ext_lan;
	}
	struct wgt_pfioc_state_kill psk;
	memset(&psk, 0, sizeof psk);
	psk.psk_af = st->af_lan;
	psk.psk_proto = st->proto;
	psk.psk_proto_variant = st->proto_variant;
	memcpy(psk.psk_ifname, st->ifname, sizeof psk.psk_ifname);
	set_kill_host(&psk.psk_src, src, st->proto);
	set_kill_host(&psk.psk_dst, dst, st->proto);
	if (ioctl(s->fd, WGT_DIOCKILLSTATES, &psk) < 0) {
		return errno == ESRCH ? 0 : -errno;
	}
	return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errAnchorNoTicket = errors.New("anchor call has no ticket, so it came from a loaded pf.conf; left in place")

func hasPFAnchor(name string) (bool, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	rc := C.wgtunnel_pf_has_anchor(cname)
	if rc < 0 {
		return false, fmt.Errorf("read pf rules: %w", unix.Errno(-rc))
	}
	return rc == 1, nil
}

func addPFAnchor(name string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	rc := C.wgtunnel_pf_add_anchor(cname)
	if rc < 0 {
		return fmt.Errorf("insert pf anchor %s: %w", name, unix.Errno(-rc))
	}
	return nil
}

func removePFAnchor(name string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	rc := C.wgtunnel_pf_remove_anchor(cname)
	if rc < 0 {
		return fmt.Errorf("remove pf anchor %s: %w", name, unix.Errno(-rc))
	}
	if rc == C.WGT_ANCHOR_SKIPPED {
		return fmt.Errorf("remove pf anchor %s: %w", name, errAnchorNoTicket)
	}
	return nil
}

type pfSnap struct {
	p *C.struct_pf_snap
}

func openPFSnap() (*pfSnap, error) {
	var errn C.int
	p := C.wgtunnel_pf_snap_open(&errn)
	if p == nil {
		if errn == 0 {
			errn = C.int(unix.EIO)
		}
		return nil, fmt.Errorf("read pf states: %w", unix.Errno(errn))
	}
	return &pfSnap{p: p}, nil
}

func (s *pfSnap) close() {
	if s == nil || s.p == nil {
		return
	}
	C.wgtunnel_pf_snap_close(s.p)
	s.p = nil
}

func (s *pfSnap) count() int {
	return int(C.wgtunnel_pf_snap_count(s.p))
}

func (s *pfSnap) state(i int) (pfState, error) {
	var ifn [C.IFNAMSIZ + 1]C.char
	var local, remote [16]C.uchar
	var proto, localLen, localPort, remoteLen, remotePort C.int
	rc := C.wgtunnel_pf_snap_view(s.p, C.int(i), &ifn[0], C.int(len(ifn)), &proto,
		&local[0], &localLen, &localPort, &remote[0], &remoteLen, &remotePort)
	if rc < 0 {
		return pfState{}, fmt.Errorf("pf state %d: %w", i, unix.Errno(-rc))
	}
	return pfState{
		ifName:     C.GoString(&ifn[0]),
		proto:      uint8(proto),
		local:      addrFromPF(int(localLen), C.GoBytes(unsafe.Pointer(&local[0]), 16)),
		localPort:  uint16(localPort),
		remote:     addrFromPF(int(remoteLen), C.GoBytes(unsafe.Pointer(&remote[0]), 16)),
		remotePort: uint16(remotePort),
	}, nil
}

func (s *pfSnap) kill(i int) error {
	rc := C.wgtunnel_pf_snap_kill(s.p, C.int(i))
	if rc < 0 {
		return fmt.Errorf("kill pf state %d: %w", i, unix.Errno(-rc))
	}
	return nil
}

func addrFromPF(n int, b []byte) netip.Addr {
	switch n {
	case 4:
		return netip.AddrFrom4([4]byte(b[:4]))
	case 16:
		return netip.AddrFrom16([16]byte(b[:16])).Unmap()
	default:
		return netip.Addr{}
	}
}

// killBlockedPFStates kills every state the kill switch would not pass.
// Existing states skip the rules, so without this a flow opened before the
// block keeps working.
func killBlockedPFStates(keep pfKeep) error {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		err := killBlockedPFStatesOnce(keep)
		if err == nil || !errors.Is(err, unix.EAGAIN) {
			return err
		}
		last = err
	}
	return last
}

func killBlockedPFStatesOnce(keep pfKeep) error {
	snap, err := openPFSnap()
	if err != nil {
		return err
	}
	defer snap.close()
	n := snap.count()
	for i := 0; i < n; i++ {
		st, err := snap.state(i)
		if err != nil {
			return err
		}
		if keepPFState(st, keep) {
			continue
		}
		if err := snap.kill(i); err != nil {
			return err
		}
	}
	return nil
}
