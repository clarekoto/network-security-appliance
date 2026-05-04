from __future__ import annotations
import random
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw, sendp, get_if_hwaddr, get_if_addr
from support import ip_to_int, int_to_ip, INTERFACE_MAP, IFACE_NAMES, IFACE_NETWORKS

# ###################### Utility ######################

def format_packet(pkt):
    if IP not in pkt:
        return pkt.summary()
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    if proto == PROTO_ICMP:
        t = pkt[ICMP].type if ICMP in pkt else "?"
        names = {0: "echo-reply", 8: "echo-request", 3: "unreachable", 11: "time-exceeded"}
        return f"ICMP  {src} -> {dst}  ({names.get(t, f'type {t}')})"
    elif proto == PROTO_TCP and TCP in pkt:
        flags = pkt[TCP].flags
        return f"TCP   {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}  [{flags}]"
    elif proto == PROTO_UDP and UDP in pkt:
        return f"UDP   {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
    return pkt.summary()

##################### CONSTANTS ########################

# ICMP policy
MAX_ICMP_PAYLOAD_BYTES = 64   # ping payloads larger than this are treated as tunnelling attempts
MAX_PING_WINDOW = 5           # max consecutive pings allowed before rate-limiting kicks in
IP_HEADER_SIZE = 20           # standard IPv4 header size in bytes (no options)
ECHO_REQUEST = 8              # ICMP type 8 = echo request (ping)

# TCP policy
MAX_INCOMPLETE_CONNECTIONS = 100  # SYN flood threshold: drop + flush table when exceeded

# Ephemeral port range for PAT
EPHEMERAL_PORT_MIN = 49152    
EPHEMERAL_PORT_MAX = 65535

# Protocol numbers 
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# Port numbers
SSH_PORT   = 22
DNS_PORT   = 53
HTTP_PORT  = 80
HTTPS_PORT = 443

# TCP flag values (after URG and PSH are masked out)
TCP_SYN     = 2
TCP_ACK     = 16
TCP_SYN_ACK = 18

# Hardcoded policy IPs
DMZ_WEB_PROXY  = "10.1.0.54"    # all inbound HTTP/HTTPS from ext is forwarded to this host
DMZ_JUMP_BOX   = "10.1.0.92"    # all inbound SSH from ext is forwarded to this host
MGT_TRUSTED_IP = "192.168.96.9" # only this IP may SSH into the management interface

# Bitmasks for each TCP flag — used to isolate or strip individual flags from the flags byte
FLAG_MASKS = {
    "CWR": 0b10000000, "ECE": 0b01000000, "URG": 0b00100000,
    "ACK": 0b00010000, "PSH": 0b00001000, "RST": 0b00000100,
    "SYN": 0b00000010, "FIN": 0b00000001
}

# Default MAC addresses for each logical interface — overwritten at startup with live values
STR_MACS = {
    "mgt": "ee:21:c0:9c:80:87",
    "int": "8e:e8:02:3a:00:f9",
    "dmz": "46:49:15:3d:47:15",
    "ext": "a6:6a:20:d1:68:d4"
}


######################## INTERFACES #############################

class Interface:
    """
    Represents a single network interface on the appliance.
    Stores the logical name, MAC address, subnet mask, and IP address.
    Handles sending packets out on the corresponding physical interface.
    """

    def __init__(self, name, mac_address, mask, ip_address):
        self.name = name         # logical name: mgt, int, dmz, ext
        self.mac = mac_address   # MAC address of the physical interface
        self.mask = mask         # subnet mask
        self.ip_address = ip_address  # IP address of the interface

    def get_mac(self):
        return self.mac

    def set_mac(self, mac):
        self.mac = mac

    def get_ip(self):
        return self.ip_address

    def set_ip(self, ip):
        self.ip_address = ip

    def get_mask(self):
        return self.mask

    def set_mask(self, mask):
        self.mask = mask

    def send_packet(self, packet):
        # Look up the physical interface name and send the packet
        iface = IFACE_NAMES.get(self.name)
        if iface:
            sendp(packet, iface=iface, verbose=False)


class InterfaceHandler:
    """
    Manages the network interfaces (mgt, int, dmz, ext).
    Reads MAC addresses and IPs dynamically from the live interfaces at startup.
    Responsible for dispatching outbound packets to the correct interface.
    """

    def __init__(self):
        # Read live MAC and IP from each physical interface so the appliance
        self.mgt = Interface("mgt", get_if_hwaddr(IFACE_NAMES.get("mgt")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("mgt")))
        self.int = Interface("int", get_if_hwaddr(IFACE_NAMES.get("int")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("int")))
        self.dmz = Interface("dmz", get_if_hwaddr(IFACE_NAMES.get("dmz")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("dmz")))
        self.ext = Interface("ext", get_if_hwaddr(IFACE_NAMES.get("ext")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("ext")))

        # Update the global MAC table
        STR_MACS["mgt"] = self.mgt.get_mac()
        STR_MACS["int"] = self.int.get_mac()
        STR_MACS["dmz"] = self.dmz.get_mac()
        STR_MACS["ext"] = self.ext.get_mac()

    def send_packet(self, interface: str, packet):
        """Send a packet out on the right interface."""
        if interface == "mgt":
            self.mgt_packet(packet)
        elif interface == "int":
            self.int.send_packet(packet)
        elif interface == "dmz":
            self.dmz.send_packet(packet)
        elif interface == "ext":
            self.ext.send_packet(packet)

    def mgt_packet(self, packet):
        """Management packets are destined for the appliance itself, not forwarded."""
        print(f"Actioned management packet {format_packet(packet)}")

    def get_int_interface(self):
        return self.int

    def get_dmz_interface(self):
        return self.dmz

    def get_mgt_interface(self):
        return self.mgt

    def get_ext_interface(self):
        return self.ext


class PatTable:
    """
    Port Address Translation table.
    Maps internal (ip, port) pairs to a unique external port on 130.102.184.1,
    allowing multiple internal hosts to share a single public IP.
    """

    def __init__(self):
        self.table: dict = {}

    def set_pat(self, in_address: str, in_port: int, out_port: int):
        """Add a new PAT entry if one doesn't already exist for this (ip, port) pair."""
        if (in_address, in_port) not in self.table:
            self.table[(in_address, in_port)] = out_port
            print(f"NAT: allocate {in_address}:{in_port} -> 130.102.184.1:{out_port}")

    def get_unused_port(self) -> int:
        """Pick a random ephemeral port that isn't already allocated in the table."""
        port = random.randint(EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX)
        while port in self.table.values():
            port = random.randint(EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX)
        return port

    def get_pat_in(self, out_port: int):
        """Return 'ip:port' string for a given external port, or None."""
        for (in_address, in_port), port in self.table.items():
            if port == out_port:
                return f"{in_address}:{in_port}"
        return None

    def get_pat_in_actual(self, out_port: int):
        """Return (in_address, in_port) tuple for a given external port."""
        for (in_address, in_port), port in self.table.items():
            if port == out_port:
                return in_address, in_port
        return None, None

    def get_pat_out(self, in_address: str, in_port: int):
        """Return the external port for a given internal address and port."""
        return self.table.get((in_address, in_port))


#########################  Connections ######################## 

class Connections:
    """
    Stateful connection tracking table.
    Each entry records the state of a flow as seen on a specific NIC.
    Two entries are created per connection — one for each direction — so that
    both ingress and egress sides can look up state independently.
    """

    def __init__(self):
        self.table: dict = {}

    def add_or_update(self, nic, proto, src_ip, src_port, dst_ip, dst_port, state):
        """Insert or overwrite the state for a connection tuple."""
        self.table[(nic, proto, src_ip, src_port, dst_ip, dst_port)] = state

    def state(self, nic, proto, src_ip, src_port, dst_ip, dst_port):
        """Look up the state of a connection, or return None if not tracked."""
        return self.table.get((nic, proto, src_ip, src_port, dst_ip, dst_port))

    def clear_table(self):
        """Remove all incomplete (syn_sent) connections — used during SYN flood mitigation."""
        self.table = {k: v for k, v in self.table.items() if v != "syn_sent"}

    def print_table(self):
        if not self.table:
            print("Connections table is empty.")
            return
        print("Current connections:")
        for (nic, proto, src_ip, src_port, dst_ip, dst_port), state in self.table.items():
            print(f"  [{state.upper()}] {nic} | proto={proto} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


########################  RouteTable ######################## 

class RouteTable:
    """
    Resolves a destination IP address to the logical egress interface name.
    All configured networks are /24, so a single mask covers every case.
    Defaults to 'ext' if the address doesn't belong to any internal subnet.
    """

    MASK = 0xffffff00 

    def resolve(self, ip: str) -> str:
        """Return the logical interface name that owns the subnet containing ip."""
        network_ip = int_to_ip(ip_to_int(ip) & self.MASK)
        interface = IFACE_NETWORKS.get(network_ip)
        if interface is not None:
            return interface
        # No internal subnet matched,route to the external interface
        return "ext"


######################## PacketEngine ######################## 

class PacketEngine:
    """
    Core firewall engine. Responsible for parsing, inspecting, and routing packets.
    Maintains state across packets via the connection table,
    PAT translation table, and ping rate-limiting counters.
    """

    def __init__(self, ih: InterfaceHandler):
        self.ih = ih                      # interface handler for sending packets
        self.rt = RouteTable()            # resolves destination IPs to egress interfaces
        self.pt = PatTable()              # PAT table for outbound NAT
        self.connections = Connections()  # stateful connection tracking
        self.ping_window = 0             # counts consecutive pings in the current window
        self.non_ping = 0                # counts non-ping packets since the last ping
        self.incomplete_num = 0          # counts half-open TCP connections (SYN sent, not yet established)
        self.curr_packet: dict = {}      # parsed fields of the packet currently being processed

    def parse_packet(self, pkt, ingress: str) -> dict:
        """Extract all relevant fields from a Scapy packet into a flat dictionary."""
        info = {}
        info["ingress"] = ingress
        info["src_mac"] = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"
        info["dest_mac"] = pkt[Ether].dst if Ether in pkt else "00:00:00:00:00:00"
        info["protocol"] = pkt[IP].proto  
        info["src_ip"] = pkt[IP].src
        info["dest_ip"] = pkt[IP].dst
        # Determine which interface to send the reply out on based on the destination IP
        info["egress"] = self.rt.resolve(info["dest_ip"])

        # Set defaults so all keys always exist regardless of protocol
        info["src_port"] = 0
        info["dest_port"] = 0
        info["flags"] = 0
        info["seq"] = 0
        info["ack"] = 0
        info["payload"] = b""
        info["bytes"] = 0
        info["type"] = 0
        info["code"] = 0
        info["icmp_id"] = 0
        info["icmp_seq"] = 0

        if ICMP in pkt:
            info["type"] = pkt[ICMP].type
            info["code"] = pkt[ICMP].code
            info["icmp_id"] = getattr(pkt[ICMP], "id", 0)
            info["icmp_seq"] = getattr(pkt[ICMP], "seq", 0)
            info["payload"] = bytes(pkt[ICMP].payload)
            # Store total IP packet size to check for oversized payloads later
            info["bytes"] = len(bytes(pkt[IP]))

        if TCP in pkt:
            # Silently remove URG and PSH flags, policy ignores them and they would
            # otherwise interfere with flag comparisons in check_packet
            raw_flags = int(pkt[TCP].flags)
            info["flags"] = raw_flags & ~(FLAG_MASKS["URG"] | FLAG_MASKS["PSH"])
            info["src_port"] = pkt[TCP].sport
            info["dest_port"] = pkt[TCP].dport
            info["seq"] = pkt[TCP].seq
            info["ack"] = pkt[TCP].ack
            info["payload"] = bytes(pkt[TCP].payload)

        elif UDP in pkt:
            info["src_port"] = pkt[UDP].sport
            info["dest_port"] = pkt[UDP].dport
            info["payload"] = bytes(pkt[UDP].payload)

        return info

    def create_echo_reply(self, p: dict):
        """Build an ICMP echo reply, swapping src/dst and setting type to 0 (echo-reply)."""
        reply = (
            Ether(src=p["dest_mac"], dst=p["src_mac"]) /
            IP(src=p["dest_ip"], dst=p["src_ip"]) /
            ICMP(type=0, code=0, id=p["icmp_id"], seq=p["icmp_seq"])
        )
        if p["payload"]:
            reply /= Raw(p["payload"])
        return reply

    def create_reply(self, dest_mac, src_mac, proto, src_ip, dest_ip,
                     src_port, dest_port, seq, ack, flags, payload):
        """Build a TCP or UDP packet from explicit field values."""
        eth = Ether(src=src_mac, dst=dest_mac)
        ip  = IP(src=src_ip, dst=dest_ip)
        if proto == PROTO_TCP:
            transport = TCP(sport=src_port, dport=dest_port, seq=seq, ack=ack, flags=flags)
        else:
            transport = UDP(sport=src_port, dport=dest_port)
        pkt = eth / ip / transport
        if payload:
            pkt /= Raw(payload)
        return pkt

   ######################## Security checks ######################## 

    def check_ICMP(self, p) -> bool:
        """Apply ICMP policy: only allow echo requests within rate limit and size limit."""
        if p["type"] == ECHO_REQUEST:
            # Reject pings whose payload exceeds the limit
            if p["bytes"] - IP_HEADER_SIZE > MAX_ICMP_PAYLOAD_BYTES:
                print(f"ALERT drop: oversize ping from {p['src_ip']} ({int(p['bytes'])} bytes)")
                return False
            # Reject if too many consecutive pings have been seen
            if self.ping_window >= MAX_PING_WINDOW:
                print(f"ALERT drop: ping rate limit from {p['src_ip']}")
                return False
            # Allow the ping
            self.ping_window += 1
            self.non_ping = 0
            return True
        else:
            # All other ICMP types (redirects, unreachables from outside, etc.) are blocked
            self.non_ping += 1
            print(f"ALERT drop: ICMP type {p['type']}:{p['code']} not allowed by policy")
            return False

    def check_packet(self) -> bool:
        """Return True if the packet is allowed by policy, False to drop."""
        p = self.curr_packet

        # ICMP
        if p["protocol"] == PROTO_ICMP:
            return self.check_ICMP(p)

        # Any non-ICMP packet increments the non-ping counter, which eventually resets the ping window
        self.non_ping += 1

        # Look up this packet in connections, allow it if its already been established
        state = self.connections.state(
            p["ingress"], p["protocol"],
            p["src_ip"], p["src_port"],
            p["dest_ip"], p["dest_port"]
        )

        if state == "established":
            return True

        # Allow SYN-ACK or ACK packets that are completing an in-progress handshake
        if state == "syn_sent" and p["flags"] in (FLAG_MASKS["SYN"] | FLAG_MASKS["ACK"],  FLAG_MASKS["ACK"]):
            return True

        # --- TCP-specific checks ---
        if p["protocol"] == PROTO_TCP:

            # Management interface: only allow SSH from the single trusted host
            if p["ingress"] == "mgt":
                if p["dest_port"] != SSH_PORT or p["src_ip"] != MGT_TRUSTED_IP:
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return False
                return True

            # SYN flood protection: if too many half-open connections exist, flush and drop
            if p["flags"] == FLAG_MASKS["SYN"]:
                if self.incomplete_num >= MAX_INCOMPLETE_CONNECTIONS:
                    print("ALERT drop: too many incomplete connections")
                    self.connections.clear_table()
                    self.incomplete_num = 0
                    return False

            # int or dmz → ext DNS (TCP DNS is uncommon but valid for large responses)
            if p["ingress"] in ("int", "dmz"):
                if p["dest_port"] == DNS_PORT and p["egress"] == "ext":
                    return True

            # int → HTTP/HTTPS outbound to ext or dmz web proxy
            if p["ingress"] == "int":
                if p["dest_port"] in (HTTP_PORT, HTTPS_PORT) and p["egress"] in ("ext", "dmz"):
                    return True
                # int → SSH outbound to ext or dmz jump box
                if p["dest_port"] == SSH_PORT and p["egress"] in ("ext", "dmz"):
                    return True
                # SSH reply coming back from dmz to int (src port is 22)
                if p["src_port"] == SSH_PORT and p["egress"] == "dmz":
                    return True

            # dmz jump box → int (allows the jump box to initiate connections inward)
            if p["ingress"] == "dmz":
                if p["src_ip"] == DMZ_JUMP_BOX and p["egress"] == "int":
                    return True
                if p["dest_port"] == SSH_PORT and p["egress"] == "int":
                    return True

            # ext inbound: only HTTP/HTTPS (→ proxy) and SSH (→ jump box) are permitted
            if p["ingress"] == "ext":
                if p["dest_port"] in (HTTP_PORT, HTTPS_PORT, SSH_PORT):
                    return True
                # Silently drop inbound DNS queries — the appliance does not serve DNS
                if p["src_port"] == DNS_PORT:
                    return False

        # --- UDP-specific checks ---
        if p["protocol"] == PROTO_UDP:
            # int or dmz → ext DNS queries (most DNS is UDP)
            if p["ingress"] in ("int", "dmz"):
                if p["dest_port"] == DNS_PORT and p["egress"] == "ext":
                    return True
            # ext → int/dmz: only allow DNS replies that match an existing PAT entry
            if p["ingress"] == "ext":
                if p["src_port"] == DNS_PORT and self.pt.get_pat_in(p["dest_port"]) is not None:
                    return True
                # Silently drop unsolicited inbound DNS queries
                if p["dest_port"] == DNS_PORT:
                    return False

        print("ALERT drop: new incoming TCP not allowed by policy")
        return False

   ######################## Helpers ########################

    def track_bidirectional(self, iface_a, src_ip, src_port, dst_ip, dst_port, iface_b, state):
        """
        Register a connection on both NICs so state lookups work from either side.
        iface_a gets the forward entry (src→dst) and iface_b gets the reverse (dst→src).
        """
        proto = self.curr_packet["protocol"]
        self.connections.add_or_update(iface_a, proto, src_ip, src_port, dst_ip, dst_port, state)
        self.connections.add_or_update(iface_b, proto, dst_ip, dst_port, src_ip, src_port, state)

    def track_pat_connection(self, ingress, dest_ip, dest_port, out_port, state):
        """
        Register both sides of a PAT connection.
        The ext entry records the flow as seen from outside (dest→130.102.184.1:out_port).
        The ingress entry records the original internal flow (src→dest).
        """
        p = self.curr_packet
        proto = p["protocol"]
        self.connections.add_or_update("ext", proto, dest_ip, dest_port, "130.102.184.1", out_port, state)
        self.connections.add_or_update(ingress, proto, p["src_ip"], p["src_port"], dest_ip, dest_port, state)

    def track_tcp_handshake(self) -> tuple:
        """
        Advance TCP connection state for a new or in-progress SYN/ACK handshake.
        - New connection (state None): must be a SYN; increments incomplete_num.
        - Completing handshake (syn_sent + ACK): decrements incomplete_num, moves to established.
        Returns (new_state, drop) where drop=True means the packet should be rejected.
        """
        p = self.curr_packet
        state = self.state()
        new_state = "syn_sent"
        if state is None:
            # First packet of a new connection must be a SYN
            if p["flags"] != FLAG_MASKS["SYN"]:
                print("ALERT drop: new incoming TCP not allowed by policy")
                return None, True
            self.incomplete_num += 1
        elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
            # Handshake completing — move to established and free the incomplete slot
            self.incomplete_num -= 1
            new_state = "established"
        return new_state, False

    def reply_via_pat(self, src_port: int = None, use_src_mac: bool = False, alert: bool = False):
        """
        Route an ext reply back to the original internal host by reversing the PAT lookup.
        src_port: override the source port in the reply (e.g. SSH_PORT, DNS_PORT); defaults to p["src_port"].
        use_src_mac: set the Ethernet dst to p["src_mac"] instead of p["dest_mac"] (needed for DNS).
        alert: print an ALERT message if no PAT entry is found for this destination port.
        """
        p = self.curr_packet
        # Look up which internal host originally made this connection
        dest_ip, dest_port = self.pt.get_pat_in_actual(p["dest_port"])
        if dest_ip is None:
            # No PAT entry means this is an unsolicited inbound packet
            if alert:
                print("ALERT drop: new incoming TCP not allowed by policy")
            return None
        # Resolve which internal interface the original host lives on
        egress = self.rt.resolve(dest_ip)
        sport = src_port if src_port is not None else p["src_port"]
        dst_mac = p["src_mac"] if use_src_mac else p["dest_mac"]
        return self.create_reply(
            dst_mac, STR_MACS[egress], p["protocol"],
            p["src_ip"], dest_ip,
            sport, dest_port,
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

   ########################  TCP/UDP ######################## 

    def handle_TCP_UDP(self):
        """Dispatch an allowed TCP/UDP packet to the correct handler based on ingress/port."""
        p = self.curr_packet

        if p["ingress"] in ("int", "dmz") and p["dest_port"] == DNS_PORT and p["egress"] == "ext":
            return self.handle_dns_outbound()
        if p["ingress"] == "int" and p["dest_port"] in (HTTP_PORT, HTTPS_PORT):
            return self.handle_int_http()
        if p["ingress"] == "int" and p["dest_port"] == SSH_PORT:
            return self.handle_int_ssh_outbound()
        if p["ingress"] == "int" and p["src_port"] == SSH_PORT and p["egress"] == "dmz":
            return self.handle_int_ssh_reply()
        if p["ingress"] == "dmz" and p["src_port"] in (HTTP_PORT, HTTPS_PORT):
            return self.handle_dmz_http_reply()
        if p["ingress"] == "dmz" and p["src_port"] == SSH_PORT:
            return self.handle_dmz_ssh_reply()
        if p["ingress"] == "dmz" and p["dest_port"] == SSH_PORT and p["egress"] == "int":
            return self.handle_dmz_ssh_to_int()
        if p["ingress"] == "ext" and p["dest_port"] == SSH_PORT:
            return self.handle_ext_ssh_inbound()
        if p["ingress"] == "ext" and p["src_port"] == SSH_PORT:
            return self.handle_ext_ssh_reply()
        if p["ingress"] == "ext" and p["dest_port"] in (HTTP_PORT, HTTPS_PORT):
            return self.handle_ext_http_inbound()
        if p["ingress"] == "ext" and p["src_port"] in (HTTP_PORT, HTTPS_PORT):
            return self.handle_ext_http_reply()
        if p["ingress"] == "ext" and p["src_port"] == DNS_PORT:
            return self.handle_ext_dns_reply()

        return None

    def state(self):
        """Return the current connection state for the packet being processed."""
        p = self.curr_packet
        return self.connections.state(
            p["ingress"], p["protocol"],
            p["src_ip"], p["src_port"],
            p["dest_ip"], p["dest_port"]
        )

    def handle_dns_outbound(self):
        """int or dmz → ext DNS query with PAT. Supports both UDP (stateless) and TCP DNS."""
        p = self.curr_packet
        state = self.state()
        if state is None:
            # First packet: determine state based on protocol/flags
            # TCP DNS starts with a SYN; UDP DNS has no handshake so goes straight to established
            new_state = "syn_sent" if (p["protocol"] == PROTO_TCP and p["flags"] == FLAG_MASKS["SYN"]) else "established"
            if new_state == "syn_sent":
                self.incomplete_num += 1
            # Allocate a PAT port and register the connection on both sides
            out_port = self.pt.get_unused_port()
            self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
            self.track_pat_connection(p["ingress"], p["dest_ip"], DNS_PORT, out_port, new_state)
        elif state == "syn_sent" and p["protocol"] == PROTO_TCP and p["flags"] == FLAG_MASKS["ACK"]:
            # TCP DNS handshake completing — move to established
            self.incomplete_num -= 1
            out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
            self.track_pat_connection(p["ingress"], p["dest_ip"], DNS_PORT, out_port, "established")
        # Forward the packet with the PAT-translated source port
        out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
        return self.create_reply(
            p["src_mac"], STR_MACS["ext"], p["protocol"],
            "130.102.184.1", p["dest_ip"],
            out_port, p["dest_port"],
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_int_http(self):
        """int → HTTP/HTTPS outbound. Uses PAT when going to ext; forwards directly to dmz."""
        p = self.curr_packet
        state = self.state()
        new_state = "established"
        if state is None:
            if p["flags"] == FLAG_MASKS["SYN"]:
                # New TCP connection — allocate PAT port now so it's ready for both branches
                self.incomplete_num += 1
                new_state = "syn_sent"
            if p["egress"] == "ext":
                out_port = self.pt.get_unused_port()
                self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
        elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
            # Handshake completing
            self.incomplete_num -= 1
        if p["egress"] == "ext":
            # Rewrite source to the appliance's public IP via PAT
            out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
            self.track_pat_connection("int", p["dest_ip"], p["dest_port"], out_port, new_state)
            return self.create_reply(
                p["dest_mac"], STR_MACS["ext"], p["protocol"],
                "130.102.184.1", p["dest_ip"],
                out_port, p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )
        elif p["egress"] == "dmz":
            # No PAT needed, forward directly to the dmz web proxy
            self.track_bidirectional("int", p["src_ip"], p["src_port"], p["dest_ip"], p["dest_port"], "dmz", new_state)
            return self.create_reply(
                p["dest_mac"], STR_MACS["dmz"], p["protocol"],
                p["src_ip"], p["dest_ip"],
                p["src_port"], p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

    def handle_int_ssh_outbound(self):
        """int → SSH outbound. Uses PAT for ext; forwards directly for dmz."""
        p = self.curr_packet
        state = self.state()
        if p["egress"] == "ext":
            if state is None and p["flags"] == FLAG_MASKS["SYN"]:
                # New SSH connection to external host, allocate a PAT port
                self.incomplete_num += 1
                out_port = self.pt.get_unused_port()
                self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
                self.track_pat_connection("int", p["dest_ip"], SSH_PORT, out_port, "syn_sent")
            elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                # Handshake completing, update connection state to established
                self.incomplete_num -= 1
                out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
                self.track_pat_connection("int", p["dest_ip"], SSH_PORT, out_port, "established")
            elif state != "established":
                # Mid-flow packet with no tracked state , drop it
                print("ALERT drop: new incoming TCP not allowed by policy")
                return None
            out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
            return self.create_reply(
                p["src_mac"], STR_MACS["ext"], p["protocol"],
                "130.102.184.1", p["dest_ip"],
                out_port, SSH_PORT,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )
        if p["egress"] == "dmz":
            # SSH to dmz jump box, no PAT needed, forward directly
            new_state, drop = self.track_tcp_handshake()
            if drop:
                return None
            self.track_bidirectional("int", p["src_ip"], p["src_port"], p["dest_ip"], SSH_PORT, "dmz", new_state)
            return self.create_reply(
                p["dest_mac"], STR_MACS["dmz"], p["protocol"],
                p["src_ip"], p["dest_ip"],
                p["src_port"], SSH_PORT,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

    def handle_int_ssh_reply(self):
        """SSH reply from dmz arriving back on the int interface."""
        p = self.curr_packet
        new_state, drop = self.track_tcp_handshake()
        if drop:
            return None
        # Track with fixed SSH_PORT as the source because replies always come from port 22
        self.track_bidirectional("int", p["src_ip"], SSH_PORT, p["dest_ip"], p["dest_port"], "dmz", new_state)
        return self.create_reply(
            p["dest_mac"], STR_MACS["dmz"], p["protocol"],
            p["src_ip"], p["dest_ip"],
            SSH_PORT, p["dest_port"],
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_dmz_http_reply(self):
        """dmz web proxy replying to an HTTP/HTTPS request from int or ext."""
        p = self.curr_packet
        state = self.state()
        if state is None:
            # No matching connection, this is an unsolicited reply, drop it
            return None
        if state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
            # Handshake completing, mark connection established on both NICs
            # Both entries use the same perspective (dest→src) because the proxy is the responder
            self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], p["src_port"], "established")
            self.connections.add_or_update(p["egress"], p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], p["src_port"], "established")
        # If the reply is heading to ext, rewrite source to the public IP
        src_ip = "130.102.184.1" if p["egress"] == "ext" else p["src_ip"]
        return self.create_reply(
            p["dest_mac"], STR_MACS[p["egress"]], p["protocol"],
            src_ip, p["dest_ip"],
            p["src_port"], p["dest_port"],
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_dmz_ssh_reply(self):
        """dmz jump box replying to an SSH session (back to ext or int)."""
        p = self.curr_packet
        state = self.state()
        if state is None:
            # No tracked session, the jump box shouldn't be sending unsolicited SSH
            print("ALERT drop: new incoming TCP not allowed by policy")
            return None
        if p["egress"] == "ext":
            # Reply going back to an external client, rewrite to public IP
            return self.create_reply(
                p["dest_mac"], STR_MACS["ext"], p["protocol"],
                "130.102.184.1", p["dest_ip"],
                SSH_PORT, p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )
        if p["egress"] == "int":
            # Reply going back to an internal host, forward as-is
            return self.create_reply(
                p["dest_mac"], STR_MACS["int"], p["protocol"],
                p["src_ip"], p["dest_ip"],
                SSH_PORT, p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

    def handle_dmz_ssh_to_int(self):
        """dmz jump box initiating an SSH connection to an internal host."""
        p = self.curr_packet
        new_state, drop = self.track_tcp_handshake()
        if drop:
            return None
        self.track_bidirectional("dmz", p["src_ip"], p["src_port"], p["dest_ip"], SSH_PORT, "int", new_state)
        return self.create_reply(
            p["dest_mac"], STR_MACS["int"], p["protocol"],
            p["src_ip"], p["dest_ip"],
            p["src_port"], SSH_PORT,
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_ext_ssh_inbound(self):
        """ext → SSH inbound. Redirects to the dmz jump box regardless of original destination."""
        p = self.curr_packet
        new_state, drop = self.track_tcp_handshake()
        if drop:
            return None
        # Overwrite egress and dest_ip to force traffic to the jump box
        p["egress"] = "dmz"
        p["dest_ip"] = DMZ_JUMP_BOX
        self.track_bidirectional("ext", p["src_ip"], p["src_port"], DMZ_JUMP_BOX, SSH_PORT, "dmz", new_state)
        return self.create_reply(
            p["src_mac"], STR_MACS["dmz"], p["protocol"],
            p["src_ip"], DMZ_JUMP_BOX,
            p["src_port"], SSH_PORT,
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_ext_ssh_reply(self):
        """ext SSH reply routed back to the internal host that initiated the connection via PAT."""
        return self.reply_via_pat(src_port=SSH_PORT, alert=True)

    def handle_ext_http_inbound(self):
        """ext → HTTP/HTTPS inbound. Redirects to the dmz web proxy regardless of original destination."""
        p = self.curr_packet
        state = self.state()
        new_state = "established"
        if state is None:
            if p["protocol"] == PROTO_TCP and p["flags"] == FLAG_MASKS["SYN"]:
                # New TCP connection from ext
                self.incomplete_num += 1
                new_state = "syn_sent"
        elif state == "syn_sent":
            if p["protocol"] == PROTO_TCP and p["flags"] == FLAG_MASKS["ACK"]:
                # Handshake completing
                self.incomplete_num -= 1
                new_state = "established"
            else:
                new_state = "syn_sent"
        # Record the ext entry using the original destination IP (the public-facing address)
        # so that subsequent packets from ext can still match this connection entry
        self.connections.add_or_update("ext", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], p["dest_port"], new_state)
        # Now overwrite dest_ip and egress to redirect to the proxy
        p["egress"] = "dmz"
        p["dest_ip"] = DMZ_WEB_PROXY
        # The dmz entry uses DMZ_WEB_PROXY as the source because that's who will reply
        self.connections.add_or_update("dmz", p["protocol"], DMZ_WEB_PROXY, p["dest_port"], p["src_ip"], p["src_port"], new_state)
        return self.create_reply(
            p["src_mac"], STR_MACS["dmz"], p["protocol"],
            p["src_ip"], DMZ_WEB_PROXY,
            p["src_port"], p["dest_port"],
            p["seq"], p["ack"], p["flags"], p["payload"]
        )

    def handle_ext_http_reply(self):
        """ext HTTP/HTTPS reply routed back to the internal host that initiated the connection via PAT."""
        return self.reply_via_pat()

    def handle_ext_dns_reply(self):
        """ext DNS reply routed back to the internal host that initiated the query via PAT."""
        # DNS replies always come from port 53 (src_mac differs from HTTP because the
        # DNS query was sent out with the querier's MAC rather than the gateway's)
        return self.reply_via_pat(src_port=DNS_PORT, use_src_mac=True)


    def process_packet(self, pkt, ingress: str):
        """Entry point for every packet. Parse, check policy, then route."""
        if IP not in pkt:
            return

        self.curr_packet = self.parse_packet(pkt, ingress)
        p = self.curr_packet

        if not self.check_packet():
            return

        # Reset ping window after enough non-ping packets have been seen
        if self.non_ping >= MAX_PING_WINDOW:
            self.non_ping = 0
            self.ping_window = 0

        # Route by protocol
        if p["protocol"] == PROTO_ICMP:
            reply = self.create_echo_reply(p)
        elif p["ingress"] == "mgt":
            reply = pkt   # Management packets are consumed by the appliance, not forwarded
        else:
            reply = self.handle_TCP_UDP()

        if reply is None:
            return

        self.route_packet(p["egress"], reply)

    def route_packet(self, interface: str, packet):
        """Log and send a packet out on the given logical interface."""
        print(f"ROUTE {interface:<4} | {format_packet(packet)}")
        self.ih.send_packet(interface, packet)


def main():
    ih = InterfaceHandler()
    pe = PacketEngine(ih)
    print("Listening...")

    # Collect all appliance IPs to filter out our own outbound packets.
    # Includes the public PAT IP so re-sniffed outbound NAT packets are ignored.
    own_ips = {ih.mgt.get_ip(), ih.int.get_ip(), ih.dmz.get_ip(), ih.ext.get_ip(), "130.102.184.1"}

    def handle(pkt):
        try:
            # Skip non-IP packets like ARP, the appliance doesn't handle them
            if IP not in pkt:
                return
            # Ignore packets we sent ourselves to prevent a feedback loop,
            # since sniff captures all traffic on the interface including our own output
            if pkt[IP].src in own_ips:
                return
            # Determine which logical interface this packet arrived on
            iface = getattr(pkt, "sniffed_on", None)
            ingress = INTERFACE_MAP.get(iface, "ext")
            pe.process_packet(pkt, ingress)
        except Exception as e:
            print(f"Error processing packet: {e}")

    own_ip_list = list(own_ips)
    # exclude management SSH traffic and packets from our own interfaces
    bpf = "not port 22 and not src host " + " and not src host ".join(own_ip_list)
    sniff(prn=handle, store=False, iface=list(INTERFACE_MAP.keys()), filter=bpf)


if __name__ == "__main__":
    main()
