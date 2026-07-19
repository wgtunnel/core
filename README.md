# WG Tunnel Core

Userspace TUN middleware library for wireguard-go clients, used by the WG Tunnel Android and desktop client.

## Overview

- **WrapperTUN** — TUN adapter for intercepting tunnel packets
- **DNS Engine** — route DoH, DoT, plain, or local (for split DNS) DNS for resolution