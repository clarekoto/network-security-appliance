# Network Security Appliance
A stateful network security appliance implemented in Python, simulating a multi-interface firewall with NAT/PAT translation, DoS detection, TCP state tracking, and policy-based packet filtering. Originally built against a custom packet capture format, extended to process real network packets via Scapy.

# Overview
This project implements a software-based network security appliance that sits between four network zones — management (mgt), internal (int), DMZ (dmz), and external (ext) — and enforces a security policy across all traffic flowing between them.

The appliance inspects packets at Layer 3/4, maintains a stateful connection table, performs Port Address Translation (PAT) for outbound traffic, and detects a range of network-based attacks and policy violations in real time.

It was originally designed to process a custom binary packet capture format (.spcap), and has since been extended to capture and process real network packets from a live interface using Scapy — without modifying the core packet processing logic.

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

## Security Policy

| Traffic | Direction | Action |
|--------|-----------|--------|
| ICMP echo-request > 64 bytes | any | DROP + ALERT |
| ICMP echo-request > 5 in window | any | DROP + ALERT |
| ICMP other types | any | DROP + ALERT |
| SSH (port 22) | mgt, from 192.168.96.9 only | ALLOW |
| SSH (port 22) | ext → dmz jump box | ALLOW via PAT |
| SSH (port 22) | int → ext | ALLOW via PAT |
| SSH (port 22) | int ↔ dmz | ALLOW |
| HTTP/HTTPS (80/443) | ext → dmz web proxy | ALLOW |
| HTTP/HTTPS (80/443) | int → ext | ALLOW via PAT |
| DNS (port 53) | int/dmz → ext | ALLOW via PAT |
| DNS queries | ext inbound | SILENT DROP |
| >100 incomplete TCP connections | any | DROP all incomplete + ALERT |
| All other new inbound | any | DROP + ALERT |