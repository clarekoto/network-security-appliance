# Network Security Appliance
 
## Overview
 
This project implements a stateful firewall appliance that sits at the boundary between four network zones, management (mgt), internal (int), DMZ (dmz), and external (ext) and enforces a security policy across all traffic moving between them.
 
The appliance inspects packets at Layer 3 and 4, maintains a stateful connection table, performs Port Address Translation (PAT) for outbound traffic, and detects a range of network-based attacks and policy violations in real time.
 
It was originally designed to process a custom binary packet capture format for a university cybersecurity course, and has since been extended to capture and process real network packets from live interfaces using Scapy, without modifying the core packet processing logic.
 
---
 
## Network Topology
 
```
         Internet
            |
          [ext]  ← enp0s2 (192.168.56.2)
            |
        FIREWALL
       /    |    \
   [int]  [dmz]  [mgt]
enp0s1  enp0s3  enp0s4
192.168.64.2  192.168.57.2  192.168.58.2
 
DMZ hosts:
  Web proxy:  10.1.0.54
  Jump box:   10.1.0.92
 
MGT trusted IP: 192.168.96.9
```
 
---
 
## Network Interfaces
 
There are four logical interfaces, each mapped to a physical virtual network adapter on the Ubuntu VM.
 
**EXT** (`enp0s2`) — External facing interface. All traffic from the internet arrives here. It is the only interface exposed to untrusted traffic, which means all the attack surface is concentrated in one place and everything behind the firewall is protected. This interface has a public IP (130.102.184.1) that is visible to the internet.
 
**INT** (`enp0s1`) — Internal network interface. Where trusted internal users and devices sit. Traffic from here is allowed outbound to ext (with PAT) and to the DMZ. For packets coming from the internet, they must go through the firewall before reaching int — the internet never has a direct route to internal hosts.
 
**DMZ** (`enp0s3`) — Demilitarised zone. Hosts here need to be reachable from the internet (web proxy, SSH jump box) but should not have full access to the internal network. Putting them on a separate interface means even if a DMZ host is compromised, the attacker is still separated from int by the firewall. This is the core principle of defence in depth.
 
**MGT** (`enp0s4`) — Management interface. This is how administrators access and configure the appliance itself. Keeping it on a completely separate interface means management traffic is physically isolated from user traffic. SSH is locked down to a single trusted IP (192.168.96.9) on this interface — even if the internal or external network is compromised, an attacker still cannot reach the management interface.
 
### Why virtual network adapters?
 
In this project, virtual network adapters are added to the Ubuntu VM running in UTM. UTM creates virtual NICs that the VM treats as real network interfaces. Each adapter is connected to a different host-only network on the Mac, giving each one its own subnet. This simulates a real multi-homed firewall with separate physical ports for each network segment.
 
When a packet arrives on a physical interface, Scapy sets `pkt.sniffed_on` to the interface name (e.g. `enp0s2`). The appliance maps that to a logical name (`ext`) using `INTERFACE_MAP`, so the rest of the code never needs to know about physical interface names.
 
 
## How Routing Works
 
The `RouteTable.resolve()` method determines which interface to send a packet out on, based on the destination IP. It applies a /24 subnet mask (`0xffffff00`) and looks up the resulting network address in a table:
 
```
192.168.56.0 → ext
192.168.64.0 → int
192.168.57.0 → dmz
192.168.58.0 → mgt
anything else → ext  (default route — the internet)
```
 
For example, a packet destined for `192.168.57.5` masks to `192.168.57.0`, which resolves to `dmz`. A packet destined for `8.8.8.8` doesn't match any local subnet, so it goes out `ext`.
 
In some cases the policy overrides this, for example, all inbound HTTP from ext is always routed to the DMZ web proxy at `10.1.0.54`, regardless of what the original destination IP was.
 
## Stateful Packet Inspection
 
A stateless firewall just checks each packet in isolation against a ruleset. A **stateful** firewall tracks the state of every connection so it can tell the difference between a legitimate reply and an unsolicited inbound connection.
 
For example: an internal host sends a DNS query to `8.8.8.8`. The appliance records this connection in the state table. When the DNS reply comes back, the appliance sees it matches an existing entry and allows it through. If an unsolicited UDP packet arrived from `8.8.8.8` with no matching state entry, it would be dropped.
 
### Connection states
 
- `syn_sent` — a TCP SYN has been seen but the handshake is not yet complete (half-open connection)
- `established` — the full TCP three-way handshake has completed and the connection is active
- Two entries are created per connection, one for each direction, so state lookups work from either side of the firewall

### URG and PSH flags
 
URG and PSH flags are silently stripped from all TCP packets before any policy checks run. This prevents URG-PSH-FIN attacks, where an attacker sets these flags to try to bypass stateful inspection in some firewalls. They are stripped silently rather than dropped because they are not inherently malicious, legitimate traffic may have them set, but the policy does not process them.
 
 
## Why NAT/PAT Is Needed
 
Internal hosts use private IP addresses (e.g. `10.0.0.5`) that are not routable on the public internet. When an internal host wants to connect to the internet, the packet needs to be rewritten so it appears to come from a public IP that the internet can actually reply to.
 
**PAT (Port Address Translation)** maps many internal (IP, port) pairs to a single public IP using different port numbers to distinguish between them:
 
```
10.0.0.5:54321  →  130.102.184.1:49200
10.0.0.8:54321  →  130.102.184.1:49201
10.0.0.12:54321 →  130.102.184.1:49202
```
 
All three internal hosts share one public IP, but each gets a unique external port so replies can be routed back to the right host.
 
### Why the PAT table is needed
 
When a reply comes back from the internet to `130.102.184.1:49200`, the firewall looks up port 49200 in the PAT table, finds it maps to `10.0.0.5:54321`, and routes the reply back to the correct internal host. Without the table, the reply has nowhere to go, the internal host's real IP is not visible to the internet.
 
### Ephemeral port allocation
 
External ports are chosen randomly from the ephemeral range (49152–65535) with collision checking to ensure no two internal connections share the same external port. Once allocated, mappings persist for the lifetime of the appliance.

 
## DoS Detection and Mitigation
 
### Oversize ping (Rule 1)
 
Normal ICMP echo requests are small, 64 bytes or less. Oversized pings are used in a "ping of death" attack to crash or destabilise hosts by overwhelming buffers, or for data exfiltration by tunnelling data through ICMP payloads. Any ping with a payload exceeding 64 bytes is dropped immediately with an alert.
 
### Ping rate limiting (Rule 2)
 
A high volume of ICMP echo requests can be used as a denial-of-service attack, consuming CPU and bandwidth. The appliance tracks a rolling window: more than 5 pings without 5 non-ping packets in between triggers a rate limit alert and drops the packet. In a real appliance this would be timer-based; here it is packet-count based because the simulation does not model real-time packet arrival.
 
### SYN flood detection (Rule 16)
 
A SYN flood attack opens hundreds of half-open TCP connections to exhaust server connection tables and CPU. The appliance tracks the number of incomplete connections (SYN sent, handshake not yet complete). If this exceeds 100, the appliance drops the packet, clears all incomplete connections from the state table, and alerts. This resets state and cuts off the attack, at the cost of also dropping legitimate connections caught in the window — an acceptable trade-off in a flooding scenario.
 
 
## Policy-Based Access Control
 
### SSH on mgt restricted to one IP (Rule 6)
 
The management interface is the most privileged access point on the appliance. Restricting SSH to a single known trusted IP eliminates the risk of brute force or unauthorised access from any other host, even those on the management network.
 
### Inbound SSH to DMZ jump box (Rule 7)
 
External SSH access is funnelled to a dedicated jump box (10.1.0.92) in the DMZ rather than allowing direct access to internal hosts. If the jump box is compromised, the attacker still cannot directly reach the internal network — the firewall enforces that boundary.
 
### Inbound HTTP/HTTPS to DMZ web proxy (Rule 11)
 
All inbound web traffic is directed to a reverse proxy in the DMZ (10.1.0.54) rather than directly to internal servers. The internet never has a direct route to the internal network. The proxy can inspect or filter requests before forwarding them inward.
 
### DNS silently dropped from ext (Rule 15)
 
The appliance is not a DNS server. Inbound DNS queries from the internet are dropped silently rather than with an alert — this avoids giving the sender any indication that the host exists or is running a service.
 
### Default deny (Rule 18)
 
Any traffic not explicitly permitted is dropped and alerted. This is the fundamental principle of a secure firewall: deny everything by default and only allow what is explicitly needed.
 
## Security Policy Table
 
| Rule | Traffic | Direction | Action |
|------|---------|-----------|--------|
| 1 | ICMP echo-request > 64 bytes | any | DROP + ALERT |
| 2 | ICMP echo-request > 5 in window | any | DROP + ALERT |
| 3 | ICMP echo-request (valid) | any | REPLY with echo-reply (up to 5 at a time) |
| 4 | ICMP other types | any | DROP + ALERT |
| 5 | URG/PSH TCP flags | any | SILENT IGNORE (process as if not set) |
| 6 | SSH (port 22) | mgt, from 192.168.96.9 only | ALLOW |
| 7 | SSH (port 22) | ext → dmz jump box (10.1.0.92) | ALLOW |
| 8 | SSH (port 22) | int → ext | ALLOW via PAT |
| 9 | SSH (port 22) | int ↔ dmz | ALLOW (no PAT) |
| 10 | SSH (port 22) | dmz jump box → int | ALLOW (no PAT) |
| 11 | HTTP/HTTPS (80/443) | ext → dmz web proxy (10.1.0.54) | ALLOW |
| 12 | HTTP/HTTPS (80/443) | int → ext | ALLOW via PAT |
| 13 | HTTP/HTTPS (80/443) | replies from dmz/ext | ALLOW (established only) |
| 14 | DNS (port 53) | int/dmz → ext | ALLOW via PAT |
| 15 | DNS queries | ext inbound | SILENT DROP |
| 16 | >100 incomplete TCP connections | any | DROP all incomplete + ALERT |
| 17 | Established/related connections | any | ALLOW (return traffic) |
| 18 | All other new inbound | any | DROP + ALERT |
 
---
 
## ICMP Policy
 
Only ICMP type 8 (echo request) is permitted, up to the rate limit. All other types are dropped with an alert.
 
| Type | Code | Meaning | Why blocked |
|------|------|---------|-------------|
| 0 | 0 | Echo Reply | Unsolicited replies could be used in reflection attacks |
| 3 | 0-4 | Destination Unreachable | Reveals which hosts and ports exist — useful for reconnaissance |
| 4 | 0 | Source Quench (deprecated) | No legitimate use, can be used for flow control abuse |
| 5 | 0-1 | Redirect | Can trick hosts into routing traffic through a malicious router |
| 8 | 0 | Echo Request | **ALLOWED** (with rate and size limits) |
| 11 | 0-1 | Time Exceeded | Used by traceroute — reveals internal network topology |
| 12 | 0 | Parameter Problem | No legitimate use case in this policy |
 
The general principle is **least privilege** — if a type is not explicitly needed, it is blocked.
 
---
 
## Code Architecture
 
### Key classes
 
**`InterfaceHandler`** — Manages the four network interfaces. At startup it reads live MAC addresses and IPs from each physical interface using `get_if_hwaddr` and `get_if_addr`, so the appliance adapts automatically rather than using hardcoded values. Responsible for dispatching outbound packets to the correct physical interface via `sendp`.
 
**`PatTable`** — Maintains the PAT mapping between internal (IP, port) pairs and external ports. `set_pat` allocates a new mapping, `get_pat_out` looks up the external port for an outbound packet, and `get_pat_in_actual` reverses the lookup for an inbound reply.
 
**`Connections`** — Stateful connection tracking table. Keyed on (nic, protocol, src_ip, src_port, dst_ip, dst_port). Two entries are created per connection — one for each direction — so lookups work from either side. `clear_table` removes all syn_sent entries during SYN flood mitigation.
 
**`RouteTable`** — Resolves a destination IP to a logical egress interface using a /24 subnet mask. Defaults to `ext` for addresses outside all known subnets.
 
**`PacketEngine`** — Core processing engine. `parse_packet` extracts all relevant fields from a Scapy packet into a flat dictionary. `check_packet` applies security policy and returns True/False. `handle_TCP_UDP` dispatches to dedicated handler methods for each traffic pattern.
 
### Why `parse_packet` returns a flat dictionary
 
Separating parsing from policy keeps `check_packet` and the handler methods clean — they access `p["src_ip"]` rather than `pkt[IP].src`. It also means all protocol-specific extraction happens in one place, with safe defaults for all keys so there are no KeyErrors in handlers that don't care about a given field.
 
### Why `handle_TCP_UDP` is a dispatcher
 
Originally all routing logic was one large function with deeply nested conditionals. Each traffic pattern (DNS outbound, HTTP from int, SSH from ext) has different PAT requirements, different state tracking, and different packet rewrite rules. Splitting into dedicated handlers makes each path independently readable and testable.
 
### Helper methods
 
**`track_bidirectional`** — Registers a connection on both NICs simultaneously. Both forward and reverse entries must exist so that state lookups work from either side of the firewall.
 
**`track_pat_connection`** — Registers both sides of a PAT connection. The ext entry records the flow as seen from outside (using the public IP and allocated port). The ingress entry records the original internal flow.
 
**`track_tcp_handshake`** — Advances TCP connection state for SYN/ACK handshakes in one place. Before this was extracted, the same SYN/ACK logic was copy-pasted into every handler.
 
**`reply_via_pat`** — Handles reverse PAT lookups for all ext reply handlers. SSH, HTTP, and DNS replies all need the same operation: look up the destination port in the PAT table, find the original internal host, build and return the reply packet.
 
---
 
## Known Limitations and Future Work
 
- **No checksum recalculation** — when source/destination IPs or ports are rewritten, the IP and TCP checksums become invalid. A real forwarding device must recalculate checksums after rewriting — otherwise the receiving host's kernel will reject the packet.
- **In-memory connection table** — the state table does not survive a restart. A real appliance would persist connections to disk or use a dedicated state synchronisation mechanism for failover.
- **No ARP handling** — the appliance relies on the host OS and NIC hardware to resolve MAC addresses. A real appliance would maintain its own ARP table per interface and respond to ARP requests itself.
- **No PAT entry timeouts** — mappings persist indefinitely. A real implementation would time out entries after a period of inactivity to free up ephemeral ports.
- **No structured logging** — alerts are printed to stdout. A production appliance would write structured logs with timestamps, packet metadata, and rule identifiers for auditing and incident response.
 
## Running the Appliance
 
```bash
sudo python3 appliance.py
```
 
The appliance listens on all four interfaces simultaneously. Packets originating from the appliance's own IPs are filtered out to prevent feedback loops.
 
## Running the Tests
 
Attack scenarios (drop + alert rules):
```bash
sudo python3 test_attack.py              # run all attack tests
sudo python3 test_attack.py 1 4          # run specific tests
sudo python3 test_attack.py --help       # list all tests
```
 
Allow scenarios (permitted traffic):
```bash
sudo python3 test_allow.py               # run all allow tests
sudo python3 test_allow.py 4 9           # run specific tests
sudo python3 test_allow.py --help        # list all tests
```
 