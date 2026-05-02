# Network Security Appliance
A stateful network security appliance implemented in Python, simulating a firewall with NAT/PAT translation, DoS detection, TCP state tracking, and policy-based packet filtering. Originally built against a custom packet capture format, extended to process real network packets via Scapy.

# Overview
This project implements a software-based network security appliance that sits between four network zones management (mgt), internal (int), DMZ (dmz), and external (ext) and enforces a security policy across all traffic flowing between them.

The appliance inspects packets at Layer 3 and 4, maintains a stateful connection table, performs Port Address Translation (PAT) for outbound traffic, and detects a range of network-based attacks and policy violations in real time.

It was originally designed to process a custom binary packet capture format (.spcap), and has since been extended to capture and process real network packets from a live interface using Scapy, without modifying the core packet processing logic.

# Features
### Stateful packet inspection

* Tracks TCP connection state across all interfaces (syn_sent, established, closed)
* Allows established and related connections while blocking unsolicited inbound traffic
* Silently drops URG and PSH flags to prevent URG-PSH-FIN attacks

### NAT/PAT translation

* Outbound traffic from internal and DMZ networks is translated via PAT to the external IP (130.102.184.1)
* Ephemeral port allocation (49152–65535) with collision avoidance
* PAT table maintains persistent mappings for the lifetime of the appliance

### DoS detection and mitigation

* Detects and drops oversize ICMP ping requests (>64 bytes)
* Rate-limits ICMP echo requests — maximum 5 pings per 5 non-ping packet window
* Detects SYN flood attacks — drops and clears all incomplete connections when open half-open connections exceed 100

### Policy-based access control

* SSH on management interface restricted to a single trusted IP (192.168.96.9)
* Inbound HTTP/HTTPS routed to a DMZ web proxy (10.1.0.54)
* Inbound SSH routed to a DMZ jump box (10.1.0.92)
* DNS (TCP/UDP port 53) allowed outbound from internal and DMZ with PAT
* All other new inbound connections blocked with alert

### Multi-interface routing

* Longest-prefix match routing across four network zones
* Automatic egress interface resolution based on destination IP

## ICMP Types and Codes

| Type | Code | Meaning |
|------|------|---------|
| 0 | 0 | Echo Reply |
| 3 | 0 | Destination Unreachable — Network Unreachable |
| 3 | 1 | Destination Unreachable — Host Unreachable |
| 3 | 2 | Destination Unreachable — Protocol Unreachable |
| 3 | 3 | Destination Unreachable — Port Unreachable |
| 3 | 4 | Destination Unreachable — Fragmentation Needed |
| 4 | 0 | Source Quench (deprecated) |
| 5 | 0 | Redirect — Redirect for Network |
| 5 | 1 | Redirect — Redirect for Host |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded — TTL Expired in Transit |
| 11 | 1 | Time Exceeded — Fragment Reassembly Time Exceeded |
| 12 | 0 | Parameter Problem — Pointer indicates error |

This appliance only permits type 8 (echo request). All other ICMP types are dropped with an alert.
Allowing other ICMP types will add unnecessary attack surfaces:
* **Type 3 (Destination Unreachable)** - attackers may probe for which hosts/ports exist by monitoring which "unreachable" replies come back

* **Type 5 (Redirect)** - can be used fo routing attacks, tricking hosts into sending traffic through a malicious router

* **Type 11 (Time Exceeded)** - what *traceroute* uses, which reveals the internal network topology to an attacker

* **Type 0 (Echo Reply)** - if the firewall itself is generating replies, blocking unsolicited replies prevents reflection attacks where the netowrk is used to amplify traffic at a victim

The general principle is **least privilege**.

## Security Policy

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

## Policy Reasoning

**Rule 1 — Oversize ping drop**
Standard ICMP echo requests are small (64 bytes or less). Oversized pings are used in a "ping of death" attack to crash or destabilise hosts by sending fragmented packets that overflow buffers on reassembly. There is no legitimate reason for a ping to exceed 64 bytes.

**Rule 2 — Ping rate limit**
A high volume of ICMP echo requests can be used as a denial-of-service attack, consuming CPU and bandwidth. Limiting to 5 pings per window prevents this while allowing normal diagnostic use.

**Rule 3 — Valid ping allowed**
ICMP echo request/reply is a standard network diagnostic tool. Allowing a small number of pings lets administrators verify connectivity without opening the network to abuse.

**Rule 4 — Other ICMP types dropped**
Non-echo ICMP types (redirect, time exceeded, destination unreachable, etc.) can be abused for network mapping, route hijacking, and traffic amplification. Since the policy does not require them, dropping everything except echo requests follows the principle of least privilege.

**Rule 5 — URG/PSH flags silently ignored**
URG and PSH flags are used in URG-PSH-FIN attacks to bypass stateful inspection in some firewalls. Stripping these flags rather than dropping the packet avoids disrupting legitimate traffic while neutralising the attack vector.

**Rule 6 — SSH on mgt restricted to one IP**
The management interface is the most privileged access point on the appliance. Restricting SSH to a single known trusted IP (192.168.96.9) eliminates the risk of brute force or unauthorised access from any other host, even those on the management network.

**Rule 7 — Inbound SSH to DMZ jump box**
External SSH access is funnelled to a dedicated jump box (10.1.0.92) in the DMZ rather than allowing direct access to internal hosts. The DMZ acts as a controlled buffer — if the jump box is compromised, the attacker still cannot directly reach the internal network.

**Rules 8–10 — SSH between internal zones**
Internal hosts and DMZ servers require SSH for legitimate administration. PAT is applied when going outbound to ext to hide internal IP structure. No PAT is needed for internal zone-to-zone traffic since those IPs are not publicly routable.

**Rule 11 — Inbound HTTP/HTTPS to DMZ web proxy**
All inbound web traffic is directed to a reverse proxy in the DMZ (10.1.0.54) rather than directly to internal servers. This means the internet never has a direct route to the internal network, and the proxy can inspect or filter requests before forwarding them.

**Rules 12–13 — HTTP/HTTPS from int and replies**
Internal users need to browse the web. PAT translates their private IPs to the external IP when going out. Reply traffic is only allowed back if a matching connection exists in the state table, preventing unsolicited inbound connections masquerading as replies.

**Rule 14 — DNS outbound from int/dmz**
Hosts on the internal network and DMZ need to resolve domain names. DNS queries are allowed outbound with PAT so internal IPs are not exposed, and the state table ensures only legitimate replies are let back in.

**Rule 15 — Inbound DNS silently dropped**
The appliance is not a DNS server. Inbound DNS queries from the internet are either a misconfiguration or a reconnaissance attempt. They are dropped silently rather than with an alert to avoid giving the sender any indication that the host exists.

**Rule 16 — SYN flood detection**
A SYN flood attack opens hundreds of half-open TCP connections to exhaust server resources. Tracking incomplete connections and dropping all of them once 100 are open mitigates this by resetting state and cutting off the attack, at the cost of also dropping the legitimate connections caught in the window.

**Rule 17 — Established connections allowed**
Once a connection has been through the full TCP handshake and is in the state table, return traffic is allowed through without re-checking policy. This is what makes the firewall stateful — it tracks connections so replies are not mistaken for unsolicited inbound traffic.

**Rule 18 — Default deny**
Any traffic not explicitly permitted by the above rules is dropped and alerted. This is the fundamental principle of a secure firewall: deny everything by default and only allow what is explicitly needed.