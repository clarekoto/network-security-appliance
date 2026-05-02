from __future__ import annotations
import random
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw, sendp, get_if_hwaddr, get_if_addr
from support import ip_to_int, int_to_ip

def format_packet(pkt):
    if IP not in pkt:
        return pkt.summary()
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    if proto == 1:
        t = pkt[ICMP].type if ICMP in pkt else "?"
        names = {0: "echo-reply", 8: "echo-request", 3: "unreachable", 11: "time-exceeded"}
        return f"ICMP  {src} -> {dst}  ({names.get(t, f'type {t}')})"
    elif proto == 6 and TCP in pkt:
        flags = pkt[TCP].flags
        return f"TCP   {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}  [{flags}]"
    elif proto == 17 and UDP in pkt:
        return f"UDP   {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
    return pkt.summary()

# ---------------------- Constants ----------------------

# bitmasks for each TCP flag used to check and strip flags from the flags byte
FLAG_MASKS = {
    "CWR": 0b10000000, "ECE": 0b01000000, "URG": 0b00100000,
    "ACK": 0b00010000, "PSH": 0b00001000, "RST": 0b00000100,
    "SYN": 0b00000010, "FIN": 0b00000001
}

# default MAC addresses for each logical interface
STR_MACS = {
    "mgt": "ee:21:c0:9c:80:87",
    "int": "8e:e8:02:3a:00:f9",
    "dmz": "46:49:15:3d:47:15",
    "ext": "a6:6a:20:d1:68:d4"
}

# Map physical interface names to logical interface names
INTERFACE_MAP = {
    "enp0s1": "int",   # internal network (shared network, internet access)
    "enp0s2": "ext",   # external network (host only)
    "enp0s3": "dmz",   # DMZ (host only) - add adapter in UTM when ready
    "enp0s4": "mgt",   # management (host only) - add adapter in UTM when ready
}

# Map physical interface names for sending replies
IFACE_NAMES = {
    "int": "enp0s1",
    "ext": "enp0s2",
    "dmz": "enp0s3",
    "mgt": "enp0s4",
}

# Map network addresses to logical interface names (used by RouteTable)
IFACE_NETWORKS = {
    "192.168.58.0": "mgt",
    "192.168.64.0": "int",
    "192.168.57.0": "dmz",
    "192.168.56.0": "ext",
}


# ---------------------- Interface ----------------------

class Interface:
    def __init__(self, name, mac_address, mask, ip_address):
        self.name = name
        self.mac = mac_address
        self.mask = mask
        self.ip_address = ip_address

    def get_mac(self): return self.mac
    def set_mac(self, mac): self.mac = mac
    def get_ip(self): return self.ip_address
    def set_ip(self, ip): self.ip_address = ip
    def get_mask(self): return self.mask
    def set_mask(self, mask): self.mask = mask

    def send_packet(self, packet):
        iface = IFACE_NAMES.get(self.name)
        if iface:
            sendp(packet, iface=iface, verbose=False)



# ------------------- InterfaceHandler -------------------

class InterfaceHandler:
    def __init__(self):
        self.mgt = Interface("mgt", get_if_hwaddr(IFACE_NAMES.get("mgt")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("mgt")))
        self.int = Interface("int", get_if_hwaddr(IFACE_NAMES.get("int")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("int")))
        self.dmz = Interface("dmz", get_if_hwaddr(IFACE_NAMES.get("dmz")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("dmz")))
        self.ext = Interface("ext", get_if_hwaddr(IFACE_NAMES.get("ext")), "255.255.255.0", get_if_addr(IFACE_NAMES.get("ext")))

        # set macs
        STR_MACS["mgt"] = self.mgt.get_mac()
        STR_MACS["int"] = self.int.get_mac()
        STR_MACS["dmz"] = self.dmz.get_mac()
        STR_MACS["ext"] = self.ext.get_mac()

    def send_packet(self, interface: str, packet):
        if interface == "mgt":
            self.mgt_packet(packet)
        elif interface == "int":
            self.int.send_packet(packet)
        elif interface == "dmz":
            self.dmz.send_packet(packet)
        elif interface == "ext":
            self.ext.send_packet(packet)

    def mgt_packet(self, packet):
        print(f"ROUTE mgt | {format_packet(packet)}")

    def get_int_interface(self): return self.int
    def get_dmz_interface(self): return self.dmz
    def get_mgt_interface(self): return self.mgt
    def get_ext_interface(self): return self.ext


# ---------------------- PatTable ----------------------

class PatTable:
    def __init__(self):
        # (in_address, in_port) -> out_port
        self.table: dict = {}

    def set_pat(self, in_address: str, in_port: int, out_port: int):
        if (in_address, in_port) not in self.table:
            self.table[(in_address, in_port)] = out_port
            print(f"NAT: allocate {in_address}:{in_port} -> 130.102.184.1:{out_port}")

    def get_unused_port(self) -> int:
        port = random.randint(49152, 65535)
        while port in self.table.values():
            port = random.randint(49152, 65535)
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


# --------------------- Connections ---------------------

class Connections:
    def __init__(self):
        # (nic, proto, src_ip, src_port, dst_ip, dst_port) -> state
        self.table: dict = {}

    def add_or_update(self, nic, proto, src_ip, src_port, dst_ip, dst_port, state):
        self.table[(nic, proto, src_ip, src_port, dst_ip, dst_port)] = state

    def state(self, nic, proto, src_ip, src_port, dst_ip, dst_port):
        return self.table.get((nic, proto, src_ip, src_port, dst_ip, dst_port))

    def clear_table(self):
        """Remove all incomplete (syn_sent) connections."""
        self.table = {k: v for k, v in self.table.items() if v != "syn_sent"}

    def print_table(self):
        if not self.table:
            print("Connections table is empty.")
            return
        print("Current connections:")
        for (nic, proto, src_ip, src_port, dst_ip, dst_port), state in self.table.items():
            print(f"  [{state.upper()}] {nic} | proto={proto} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


# --------------------- RouteTable ---------------------

class RouteTable:
    def __init__(self):
        self.MASKS = [0xffffff00, 0xffff0000, 0xfffff000]

    def resolve(self, ip: str) -> str:
        ip_int = ip_to_int(ip)
        for mask in self.MASKS:
            network_ip = int_to_ip(ip_int & mask)
            interface = IFACE_NETWORKS.get(network_ip)
            if interface is not None:
                return interface
        return "ext"


# --------------------- PacketEngine --------------------

class PacketEngine:
    def __init__(self, ih: InterfaceHandler):
        self.ih = ih
        self.rt = RouteTable()
        self.pt = PatTable()
        self.connections = Connections()
        self.ping_window = 0
        self.non_ping = 0
        self.incomplete_num = 0
        self.curr_packet: dict = {}

    # -------------------- Parsing --------------------

    def parse_packet(self, pkt, ingress: str) -> dict:
        """Parse a Scapy packet into a flat info dictionary."""
        info = {}
        info["ingress"] = ingress
        info["src_mac"] = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"
        info["dest_mac"] = pkt[Ether].dst if Ether in pkt else "00:00:00:00:00:00"
        info["protocol"] = pkt[IP].proto   # 1=ICMP, 6=TCP, 17=UDP
        info["src_ip"] = pkt[IP].src
        info["dest_ip"] = pkt[IP].dst
        info["egress"] = self.rt.resolve(info["dest_ip"])

        # Defaults so all keys always exist
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
            info["bytes"] = len(bytes(pkt[IP]))

        if TCP in pkt:
            # Silently strip URG and PSH flags per policy
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

    # -------------------- Packet construction --------------------

    def create_echo_reply(self, p: dict):
        """Build an ICMP echo reply from a parsed echo request."""
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
        """Build a TCP or UDP reply packet."""
        eth = Ether(src=src_mac, dst=dest_mac)
        ip  = IP(src=src_ip, dst=dest_ip)
        if proto == 6:
            transport = TCP(sport=src_port, dport=dest_port, seq=seq, ack=ack, flags=flags)
        else:
            transport = UDP(sport=src_port, dport=dest_port)
        pkt = eth / ip / transport
        if payload:
            pkt /= Raw(payload)
        return pkt

    # -------------------- Security checks --------------------

    def check_packet(self) -> bool:
        """Return True if the packet is allowed by policy, False to drop."""
        p = self.curr_packet

        # --- ICMP ---
        if p["protocol"] == 1:
            if p["type"] == 8:  # echo-request
                if p["bytes"] > 64:
                    print(f"ALERT drop: oversize ping from {p['src_ip']} ({int(p['bytes'])} bytes)")
                    return False
                if self.ping_window >= 5:
                    print(f"ALERT drop: ping rate limit from {p['src_ip']}")
                    return False
                self.ping_window += 1
                self.non_ping = 0
                return True
            else:
                self.non_ping += 1
                print(f"ALERT drop: ICMP type {p['type']}:{p['code']} not allowed by policy")
                return False

        # Non-ICMP packet resets ping window tracking
        self.non_ping += 1

        # --- Allow already-established connections ---
        state = self.connections.state(
            p["ingress"], p["protocol"],
            p["src_ip"], p["src_port"],
            p["dest_ip"], p["dest_port"]
        )

        if state == "established":
            return True

        # Allow SYN-ACK or ACK for in-progress handshakes
        if state == "syn_sent" and p["flags"] in (
            FLAG_MASKS["SYN"] | FLAG_MASKS["ACK"],  # 18 = SYN-ACK
            FLAG_MASKS["ACK"]                        # 16 = ACK
        ):
            return True

        # --- TCP-specific checks ---
        if p["protocol"] == 6:

            # Management interface: only SSH from trusted host
            if p["ingress"] == "mgt":
                if p["dest_port"] != 22 or p["src_ip"] != "192.168.96.9":
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return False
                return True

            # SYN flood protection
            if p["flags"] == FLAG_MASKS["SYN"]:
                if self.incomplete_num >= 100:
                    print("ALERT drop: too many incomplete connections")
                    self.connections.clear_table()
                    self.incomplete_num = 0
                    return False

            # int or dmz → ext DNS
            if p["ingress"] in ("int", "dmz"):
                if p["dest_port"] == 53 and p["egress"] == "ext":
                    return True

            # int → HTTP/HTTPS or SSH outbound
            if p["ingress"] == "int":
                if p["dest_port"] in (80, 443) and p["egress"] in ("ext", "dmz"):
                    return True
                if p["dest_port"] == 22 and p["egress"] in ("ext", "dmz"):
                    return True
                if p["src_port"] == 22 and p["egress"] == "dmz":
                    return True

            # dmz jump box → int
            if p["ingress"] == "dmz":
                if p["src_ip"] == "10.1.0.92" and p["egress"] == "int":
                    return True
                if p["dest_port"] == 22 and p["egress"] == "int":
                    return True

            # ext inbound: HTTP/HTTPS → dmz proxy, SSH → dmz jump box
            if p["ingress"] == "ext":
                if p["dest_port"] in (80, 443, 22):
                    return True
                # Silently drop inbound DNS queries
                if p["src_port"] == 53:
                    return False

        # --- UDP-specific checks ---
        if p["protocol"] == 17:
            # int or dmz → ext DNS
            if p["ingress"] in ("int", "dmz"):
                if p["dest_port"] == 53 and p["egress"] == "ext":
                    return True
            # ext → int/dmz DNS reply (via PAT)
            if p["ingress"] == "ext":
                if p["src_port"] == 53 and self.pt.get_pat_in(p["dest_port"]) is not None:
                    return True
                # Silently drop new inbound DNS queries
                if p["dest_port"] == 53:
                    return False

        print("ALERT drop: new incoming TCP not allowed by policy")
        return False

    # -------------------- TCP/UDP routing --------------------

    def handle_TCP_UDP(self):
        """Route an allowed TCP/UDP packet and return the forwarded packet."""
        p = self.curr_packet
        state = self.connections.state(
            p["ingress"], p["protocol"],
            p["src_ip"], p["src_port"],
            p["dest_ip"], p["dest_port"]
        )

        # ---- int or dmz → ext DNS (with PAT) ----
        if p["ingress"] in ("int", "dmz") and p["dest_port"] == 53 and p["egress"] == "ext":
            if state is None:
                new_state = "syn_sent" if (p["protocol"] == 6 and p["flags"] == FLAG_MASKS["SYN"]) else "established"
                if new_state == "syn_sent":
                    self.incomplete_num += 1
                out_port = self.pt.get_unused_port()
                self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
                self.connections.add_or_update("ext", p["protocol"], p["dest_ip"], 53, "130.102.184.1", out_port, new_state)
                self.connections.add_or_update(p["ingress"], p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 53, new_state)
            elif state == "syn_sent" and p["protocol"] == 6 and p["flags"] == FLAG_MASKS["ACK"]:
                self.incomplete_num -= 1
                out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
                self.connections.add_or_update("ext", p["protocol"], p["dest_ip"], 53, "130.102.184.1", out_port, "established")
                self.connections.add_or_update(p["ingress"], p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 53, "established")

            out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
            return self.create_reply(
                p["src_mac"], STR_MACS["ext"], p["protocol"],
                "130.102.184.1", p["dest_ip"],
                out_port, p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- int → HTTP/HTTPS ----
        if p["ingress"] == "int" and p["dest_port"] in (80, 443):
            new_state = "established"
            if state is None:
                if p["flags"] == FLAG_MASKS["SYN"]:
                    self.incomplete_num += 1
                    new_state = "syn_sent"
                if p["egress"] == "ext":
                    out_port = self.pt.get_unused_port()
                    self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
            elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                self.incomplete_num -= 1

            if p["egress"] == "ext":
                out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
                self.connections.add_or_update("ext", p["protocol"], p["dest_ip"], p["dest_port"], "130.102.184.1", out_port, new_state)
                self.connections.add_or_update("int", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], p["dest_port"], new_state)
                return self.create_reply(
                    p["dest_mac"], STR_MACS["ext"], p["protocol"],
                    "130.102.184.1", p["dest_ip"],
                    out_port, p["dest_port"],
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )
            elif p["egress"] == "dmz":
                self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], p["src_port"], new_state)
                self.connections.add_or_update("int", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], p["dest_port"], new_state)
                return self.create_reply(
                    p["dest_mac"], STR_MACS["dmz"], p["protocol"],
                    p["src_ip"], p["dest_ip"],
                    p["src_port"], p["dest_port"],
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )

        # ---- int → SSH (outbound to ext or dmz) ----
        if p["ingress"] == "int" and p["dest_port"] == 22:
            if p["egress"] == "ext":
                if state is None and p["flags"] == FLAG_MASKS["SYN"]:
                    self.incomplete_num += 1
                    out_port = self.pt.get_unused_port()
                    self.pt.set_pat(p["src_ip"], p["src_port"], out_port)
                    self.connections.add_or_update("ext", p["protocol"], p["dest_ip"], 22, "130.102.184.1", out_port, "syn_sent")
                    self.connections.add_or_update("int", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 22, "syn_sent")
                elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                    self.incomplete_num -= 1
                    out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
                    self.connections.add_or_update("ext", p["protocol"], p["dest_ip"], 22, "130.102.184.1", out_port, "established")
                    self.connections.add_or_update("int", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 22, "established")
                elif state != "established":
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return None
                out_port = self.pt.get_pat_out(p["src_ip"], p["src_port"])
                return self.create_reply(
                    p["src_mac"], STR_MACS["ext"], p["protocol"],
                    "130.102.184.1", p["dest_ip"],
                    out_port, 22,
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )

            if p["egress"] == "dmz":
                new_state = "syn_sent"
                if state is None:
                    if p["flags"] != FLAG_MASKS["SYN"]:
                        print("ALERT drop: new incoming TCP not allowed by policy")
                        return None
                    self.incomplete_num += 1
                elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                    self.incomplete_num -= 1
                    new_state = "established"
                self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], 22, p["src_ip"], p["src_port"], new_state)
                self.connections.add_or_update("int", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 22, new_state)
                return self.create_reply(
                    p["dest_mac"], STR_MACS["dmz"], p["protocol"],
                    p["src_ip"], p["dest_ip"],
                    p["src_port"], 22,
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )

        # ---- int SSH reply from dmz (src_port == 22) ----
        if p["ingress"] == "int" and p["src_port"] == 22 and p["egress"] == "dmz":
            new_state = "syn_sent"
            if state is None:
                if p["flags"] != FLAG_MASKS["SYN"]:
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return None
                self.incomplete_num += 1
            elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                self.incomplete_num -= 1
                new_state = "established"
            self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], 22, new_state)
            self.connections.add_or_update("int", p["protocol"], p["src_ip"], 22, p["dest_ip"], p["dest_port"], new_state)
            return self.create_reply(
                p["dest_mac"], STR_MACS["dmz"], p["protocol"],
                p["src_ip"], p["dest_ip"],
                22, p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- dmz → HTTP/HTTPS replies ----
        if p["ingress"] == "dmz" and p["src_port"] in (80, 443):
            if state is None:
                return None
            if state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], p["src_port"], "established")
                self.connections.add_or_update(p["egress"], p["protocol"], p["dest_ip"], p["dest_port"], p["src_ip"], p["src_port"], "established")
            src_ip = "130.102.184.1" if p["egress"] == "ext" else p["src_ip"]
            return self.create_reply(
                p["dest_mac"], STR_MACS[p["egress"]], p["protocol"],
                src_ip, p["dest_ip"],
                p["src_port"], p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- dmz → SSH replies (back to ext or int) ----
        if p["ingress"] == "dmz" and p["src_port"] == 22:
            if state is None:
                print("ALERT drop: new incoming TCP not allowed by policy")
                return None
            if p["egress"] == "ext":
                return self.create_reply(
                    p["dest_mac"], STR_MACS["ext"], p["protocol"],
                    "130.102.184.1", p["dest_ip"],
                    22, p["dest_port"],
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )
            if p["egress"] == "int":
                return self.create_reply(
                    p["dest_mac"], STR_MACS["int"], p["protocol"],
                    p["src_ip"], p["dest_ip"],
                    22, p["dest_port"],
                    p["seq"], p["ack"], p["flags"], p["payload"]
                )

        # ---- dmz jump box → int SSH ----
        if p["ingress"] == "dmz" and p["dest_port"] == 22 and p["egress"] == "int":
            new_state = "syn_sent"
            if state is None:
                if p["flags"] != FLAG_MASKS["SYN"]:
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return None
                self.incomplete_num += 1
            elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                self.incomplete_num -= 1
                new_state = "established"
            self.connections.add_or_update("int", p["protocol"], p["dest_ip"], 22, p["src_ip"], p["src_port"], new_state)
            self.connections.add_or_update("dmz", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 22, new_state)
            return self.create_reply(
                p["dest_mac"], STR_MACS["int"], p["protocol"],
                p["src_ip"], p["dest_ip"],
                p["src_port"], 22,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- ext → SSH → dmz jump box ----
        if p["ingress"] == "ext" and p["dest_port"] == 22:
            new_state = "syn_sent"
            if state is None:
                if p["flags"] != FLAG_MASKS["SYN"]:
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return None
                self.incomplete_num += 1
            elif state == "syn_sent" and p["flags"] == FLAG_MASKS["ACK"]:
                self.incomplete_num -= 1
                new_state = "established"
            p["egress"] = "dmz"
            p["dest_ip"] = "10.1.0.92"
            self.connections.add_or_update("ext", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], 22, new_state)
            self.connections.add_or_update("dmz", p["protocol"], p["dest_ip"], 22, p["src_ip"], p["src_port"], new_state)
            return self.create_reply(
                p["src_mac"], STR_MACS["dmz"], p["protocol"],
                p["src_ip"], "10.1.0.92",
                p["src_port"], 22,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- ext → SSH reply back via PAT ----
        if p["ingress"] == "ext" and p["src_port"] == 22:
            dest_ip, dest_port = self.pt.get_pat_in_actual(p["dest_port"])
            if dest_ip is None:
                print("ALERT drop: new incoming TCP not allowed by policy")
                return None
            egress = self.rt.resolve(dest_ip)
            return self.create_reply(
                p["dest_mac"], STR_MACS[egress], p["protocol"],
                p["src_ip"], dest_ip,
                22, dest_port,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- ext → HTTP/HTTPS → dmz web proxy ----
        if p["ingress"] == "ext" and p["dest_port"] in (80, 443):
            new_state = "established"
            if state is None:
                if p["protocol"] == 6 and p["flags"] == FLAG_MASKS["SYN"]:
                    self.incomplete_num += 1
                    new_state = "syn_sent"
            elif state == "syn_sent":
                if p["protocol"] == 6 and p["flags"] == FLAG_MASKS["ACK"]:
                    self.incomplete_num -= 1
                    new_state = "established"
                else:
                    new_state = "syn_sent"
            self.connections.add_or_update("ext", p["protocol"], p["src_ip"], p["src_port"], p["dest_ip"], p["dest_port"], new_state)
            p["egress"] = "dmz"
            p["dest_ip"] = "10.1.0.54"
            self.connections.add_or_update("dmz", p["protocol"], "10.1.0.54", p["dest_port"], p["src_ip"], p["src_port"], new_state)
            return self.create_reply(
                p["src_mac"], STR_MACS["dmz"], p["protocol"],
                p["src_ip"], "10.1.0.54",
                p["src_port"], p["dest_port"],
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- ext → HTTP/HTTPS reply via PAT ----
        if p["ingress"] == "ext" and p["src_port"] in (80, 443):
            dest_ip, dest_port = self.pt.get_pat_in_actual(p["dest_port"])
            if dest_ip is None:
                return None
            egress = self.rt.resolve(dest_ip)
            return self.create_reply(
                p["dest_mac"], STR_MACS[egress], p["protocol"],
                p["src_ip"], dest_ip,
                p["src_port"], dest_port,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        # ---- ext → DNS reply via PAT ----
        if p["ingress"] == "ext" and p["src_port"] == 53:
            dest_ip, dest_port = self.pt.get_pat_in_actual(p["dest_port"])
            if dest_ip is None:
                return None
            egress = self.rt.resolve(dest_ip)
            return self.create_reply(
                p["src_mac"], STR_MACS[egress], p["protocol"],
                p["src_ip"], dest_ip,
                53, dest_port,
                p["seq"], p["ack"], p["flags"], p["payload"]
            )

        return None

    # -------------------- Main processing --------------------

    def process_packet(self, pkt, ingress: str):
        """Entry point for every packet. Parse, check, then route."""
        if IP not in pkt:
            return

        self.curr_packet = self.parse_packet(pkt, ingress)
        p = self.curr_packet

        if not self.check_packet():
            return

        # Reset ping window after 5 non-ping packets
        if self.non_ping >= 5:
            self.non_ping = 0
            self.ping_window = 0

        # Route by protocol
        if p["protocol"] == 1:
            reply = self.create_echo_reply(p)
        elif p["ingress"] == "mgt":
            reply = pkt   # management packets forwarded as-is
        else:
            reply = self.handle_TCP_UDP()

        if reply is None:
            return

        self.route_packet(p["egress"], reply)

    def route_packet(self, interface: str, packet):
        print(f"ROUTE {interface:<4} | {format_packet(packet)}")
        self.ih.send_packet(interface, packet)


# ---------------------- Entry point ----------------------

def run_appliance() -> None:
    ih = InterfaceHandler()
    pe = PacketEngine(ih)
    print("Listening on all interfaces...")

    own_ips = {ih.mgt.get_ip(), ih.int.get_ip(), ih.dmz.get_ip(), ih.ext.get_ip()}

    def handle(pkt):
        try:
            if IP not in pkt:
                return
            if pkt[IP].src in own_ips:
                return
            iface = getattr(pkt, "sniffed_on", None)
            ingress = INTERFACE_MAP.get(iface, "ext")
            pe.process_packet(pkt, ingress)
        except Exception as e:
            print(f"Error processing packet: {e}")

    own_ip_list = list(own_ips)
    bpf = "not port 22 and not src host " + " and not src host ".join(own_ip_list)
    sniff(prn=handle, store=False, iface=list(INTERFACE_MAP.keys()), filter=bpf)


def main():
    run_appliance()


if __name__ == "__main__":
    main()