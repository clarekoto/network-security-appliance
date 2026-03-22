from __future__ import annotations
import os
import sys
import struct
import random
import ipaddress
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, raw
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Any
from support import *

# ------CONSTANTS--------
# where each part in a packet starts
HEADER = {"first_byte": (0, 8), "dest_mac": (8, 48), "src_mac": (56, 48), "protocol": (120, 8), "src_ip": (128, 32), "dest_ip": (160, 32)}
# HEADER_SIZES = {"first_byte": 8, "dest_mac": 48, "src_mac": 48, "protocol": 8, "src_ip": 32, "dest_ip": 32}
TCP = {"src_port": (192, 16), "dest_port": (208, 16), "sequence": (224, 32), "ack": (256, 32), "flag": (288, 8), "payload": 296}
# TCP_SIZE = {"src_port": 16, "dest_port": 16, "sequence": 32, "ack": 32, "flag": 8}
UDP = {"src_port": (192, 16), "dest_port": (208, 16), "payload": 224}
# UDP_SIZE = {"src_port": 16, "dest_port": 16}
ICMP = {"type": (192, 8), "code": (200, 8), "header": (208, 32), "payload": 240}
# ICMP_SIZE = {"type": }
FLAG_MASKS = {"CWR": 0b10000000, "ECE": 0b01000000, "URG": 0b00100000, "ACK": 0b00010000, "PSH": 0b00001000, "RST": 0b00000100, "SYN": 0b00000010, "FIN": 0b00000001}
STR_MACS = {"mgt": "28ee5285f23a", "int": "28ee52e2b730", "dmz": "28ee524c4d70", "ext": "28ee529c61ab"}
STR_IPS = {"ext": "8266b801" }
INTERFACE_MAP = {
    "enp0s1": "ext", # my VM's main interface
    "lo": "mgt", # loopback is management
}


def scapy_to_hex(pkt):
    # convert the raw packet bytes to hex string
    # this is the same format your spcap file uses
    raw_bytes = bytes(pkt)
    return raw_bytes.hex()

class Interface:
    # have name as a variable so i can run send_packet
    def __init__(self, name, mac_address, mask, ip_address):
        self.mac = mac_address
        self.mask = mask
        self.ip_address = ip_address
        self.name = name
        
    def get_mac(self):
        return self.mac
    
    def set_mac(self, mac_address):
        self.mac = mac_address
    
    def get_ip(self):
        return self.ip_address
    
    def set_ip(self, ip_address):
        self.ip_address = ip_address
    
    def get_mask(self):
        return self.mask
    
    def set_mask(self, netmask):
        self.mask = netmask

    def get_default(self):
        return self.ip_address
    
    def set_default(self, ip_address):
        self.ip_address = ip_address

    # use .hex()
    def send_packet(self, packet: bytes):
        print(self.name + ": sent packet " + packet)

class InterfaceHandler:
    #instantiate the 4 nics here
    def __init__(self, cap_file):
        self.file = None
        if cap_file:
            self.file = open(cap_file, "r")

        self.mgt = Interface("mgt", "28:ee:52:85:f2:3a", "255.255.240.0", "192.168.96.23")
        self.int = Interface("int", "28:ee:52:e2:b7:30", "255.255.0.0", "10.0.0.1")
        self.dmz = Interface("dmz", "28:ee:52:4c:4d:70", "255.255.255.0", "10.1.0.1")
        self.ext = Interface("ext", "28:ee:52:9c:61:ab", "255.255.255.0", "130.102.184.1")
        self.IFACE_NETWORKS = {"192.168.96.0": "mgt", "10.0.0.0": "int", "10.1.0.0": "dmz", "130.102.184.0": "ext"}

    def scapy_to_custom_format(self, scapy_pkt, ingress="ext"):
        import struct

        # only handle IP packets
        if IP not in scapy_pkt:
            return None

        interface_bytes = {
            "mgt": "a8", "int": "a9",
            "dmz": "aa", "ext": "ab"
        }

        # get MACs
        if Ether in scapy_pkt:
            src_mac = scapy_pkt[Ether].src.replace(':', '')
            dst_mac = scapy_pkt[Ether].dst.replace(':', '')
        else:
            src_mac = "000000000000"
            dst_mac = "000000000000"

        # get protocol number
        proto = scapy_pkt[IP].proto
        proto_hex = format(proto, '02x')

        # get IPs as hex
        src_ip = struct.pack('!I', struct.unpack('!I', 
            inet_aton(scapy_pkt[IP].src))[0]).hex()
        dst_ip = struct.pack('!I', struct.unpack('!I', 
            inet_aton(scapy_pkt[IP].dst))[0]).hex()

        # build common header
        header = (interface_bytes[ingress] + dst_mac + src_mac +
                "0800" + proto_hex + src_ip + dst_ip)

        # add protocol specific fields
        if TCP in scapy_pkt:
            src_port = format(scapy_pkt[TCP].sport, '04x')
            dst_port = format(scapy_pkt[TCP].dport, '04x')
            seq = format(scapy_pkt[TCP].seq, '08x')
            ack = format(scapy_pkt[TCP].ack, '08x')
            flags = format(int(scapy_pkt[TCP].flags), '02x')
            payload = bytes(scapy_pkt[TCP].payload).hex()
            return header + src_port + dst_port + seq + ack + flags + payload

        elif UDP in scapy_pkt:
            src_port = format(scapy_pkt[UDP].sport, '04x')
            dst_port = format(scapy_pkt[UDP].dport, '04x')
            payload = bytes(scapy_pkt[UDP].payload).hex()
            return header + src_port + dst_port + payload

        elif ICMP in scapy_pkt:
            icmp_type = format(scapy_pkt[ICMP].type, '02x')
            icmp_code = format(scapy_pkt[ICMP].code, '02x')
            icmp_id = format(
                scapy_pkt[ICMP].id if hasattr(scapy_pkt[ICMP], 'id') else 0, 
                '04x'
            )
            icmp_seq = format(
                scapy_pkt[ICMP].seq if hasattr(scapy_pkt[ICMP], 'seq') else 0, 
                '04x'
            )
            payload = bytes(scapy_pkt[ICMP].payload).hex()
            return header + icmp_type + icmp_code + icmp_id + icmp_seq + payload

        return None

    """read “packets” from a special (again PCAP-like, but not PCAP special
    format “traffic.spcap” (packet capture) file in the same directory as the code"""
    def next_packet(self):
        data = self.file.readline()
        if not data:
            self.file.close()
            return None
        if data[0] == '#':
            return self.next_packet()
        else:
            if data[len(data) - 1] == '\n':
                data = data[0: len(data) - 1]
            return data
  
        """to “send out” packets via the appropriate
    interfaces (referenced by the 3-character string mgt/int/dmz/ext) send_packet method"""    
    def send_packet(self, interface: str, packet: bytes):
        if interface == "mgt":
            self.mgt_packet(packet)
        elif interface == "int":
            self.int.send_packet(packet)
        elif interface == "dmz":
            self.dmz.send_packet(packet)
        elif interface == "ext":
            self.ext.send_packet(packet)


        """ to be “actioned” by the simulated appliance itself, by printing a
    message “Actioned management packet ” + the entire packet as a string in hexadecimal digits."""
    def mgt_packet(self, packet: bytes):
        print("Actioned management packet " + packet)
    
    def get_int_interface(self):
        return self.int
    
    def get_dmz_interface(self):
        return self.dmz
    
    def get_mgt_interface(self):
        return self.mgt
    
    def get_ext_interface(self):
        return self.ext


    

    
class PatTable:

    def __init__(self):
        self.table = {}
    """ adds the translation to the
    table and prints the message “NAT: allocate in_address:in_port -> out_address:out_port” – these are
    never removed in our simulated appliance – once set, the same combination of in_address and in_port
    will always be assigned the same out_port (in a real appliance these would need to be removed when no
    longer used otherwise the table would fill or all available ports would be allocated);"""
    def set_pat(self, in_address: str, in_port: int, out_port: int):
        if (in_address, in_port) not in self.table:
            self.table[(in_address, in_port)] = out_port
            in_port_str = str(int(in_port, 16))
            out_port_str = str(int(out_port, 16))
            print("NAT: allocate " + in_address + ":" + in_port_str + " -> 130.102.184.1:" + out_port_str)

    """that returns a random ephemeral port number (ports 49152 – 65535) that
    is not already in the table;"""
    def get_unused_port(self):
        port = random.randint(49152, 65535)
        while port in self.table.values():
            port = random.randint(49152, 65535)
        return port


    """that returns the IP:port as a string of the IPv4-dotted-quad:port;"""
    def get_pat_in(self, out_port: int):
        for (in_address, in_port), port in self.table.items():
            if port == out_port:
                in_port_str = str(int(in_port, 16))
                return in_address + ":" + in_port_str
    
    def get_pat_in_actual(self, out_port: int):
        for (in_address, in_port), port in self.table.items():
            if port == out_port:
                return in_address, in_port
    

    """that returns the external port number."""
    def get_pat_out(self, in_address: str, in_port: int):
        for (key1, key2), port in self.table.items():
                if key1 == in_address and key2 == in_port:
                    return port

class PacketEngine:
    def __init__(self, ih: InterfaceHandler):
        self.ih = ih
        self.rt = RouteTable(ih)
        self.pt = PatTable()
        self.connections = Connections()
        self.ping_window = 0
        self.non_ping = 0
        self.packet_num = 0
        self.incomplete_num = 0

        
    # size is in bits so divide by 4 since the packet is in hex
    def read_packet(self, packet: bytes, pointer: int, size: int):
        pointer //= 4
        size //= 4
        pack = packet[pointer: pointer + size]
        return pack
    
    def str_hex_to_binary(self, chunk):
        binary = bin(int(chunk, 16))
        return int(binary, 2)

    def int_to_hex_str(self, chunk, length):
        hexa = hex(chunk)[2:]
        if len(hexa) < length:
            hexa = ((length - len(hexa)) * "0") + hexa
        
        return str(hexa)

    # new_ip will be in pv4 for 102.22. ect
    def replace_dest_ip(self, packet, new_ip):
        ip = ip_to_int(new_ip)
        ip = str(hex(ip))
        ip = ip[2:]
        if len(ip) == 7:
            ip = "0" + ip
        new_packet = packet[:HEADER["dest_ip"][0]//4] + ip + packet[HEADER["dest_ip"][0]//4 + HEADER["dest_ip"][1]//4:]
        return new_packet

    def replace_src_mac(self, packet, new_mac):
        mac = mac_to_bytes(new_mac)
        mac = mac.hex()
        new_packet = packet[:HEADER["src_mac"][0]//4] + mac + packet[HEADER["src_mac"][0]//4 + HEADER["src_mac"][1]//4:]
        return new_packet
    
    def replace_interface(self, packet, interface):
        if interface == "mgt":
            new_packet = "a8" + packet[2:]
        elif interface == "int":
            new_packet = "a9" + packet[2:]
        elif interface == "dmz":
            new_packet = "aa" + packet[2:]
        elif interface == "ext":
            new_packet = "ab" + packet[2:]

        return new_packet
    
    def create_echo_reply(self, packet):
        first_byte = self.read_packet(packet, HEADER["first_byte"][0], HEADER["first_byte"][1])
        dest_mac = self.read_packet(packet, HEADER["src_mac"][0], HEADER["src_mac"][1])
        src_mac = self.read_packet(packet, HEADER["dest_mac"][0], HEADER["dest_mac"][1])
        ethertype = "0800"
        proto = "01"
        src_ip = self.read_packet(packet, HEADER["dest_ip"][0], HEADER["dest_ip"][1])
        dest_ip = self.read_packet(packet, HEADER["src_ip"][0], HEADER["src_ip"][1])
        type = "00"
        code = "00"
        header = self.read_packet(packet, ICMP["header"][0], ICMP["header"][1])
        payload = self.read_packet(packet, ICMP["payload"], len(packet)*4 - ICMP["payload"])
        
        return first_byte + dest_mac + src_mac + ethertype + proto + src_ip + dest_ip + type + code + header + payload



    def parse_packet(self, packet):
        # return a dictionary with everything inside
        packet_info = {}
        mask = 0b00000011
        interface = mask & self.str_hex_to_binary(self.read_packet(packet, HEADER["first_byte"][0], HEADER["first_byte"][1]))
        packet_info["ingress"] = IFACE_NAMES[interface]

        packet_info["dest_mac"] = self.read_packet(packet, HEADER["dest_mac"][0], HEADER["dest_mac"][1])
        packet_info["src_mac"] = self.read_packet(packet, HEADER["src_mac"][0], HEADER["src_mac"][1])
        packet_info["protocol"] = self.read_packet(packet, HEADER["protocol"][0], HEADER["protocol"][1])
        packet_info["src_ip"] = int_to_ip(int(self.read_packet(packet, HEADER["src_ip"][0], HEADER["src_ip"][1]), 16))
        packet_info["dest_ip"] = int_to_ip(int(self.read_packet(packet, HEADER["dest_ip"][0], HEADER["dest_ip"][1]), 16))
        packet_info["egress"] = self.rt.resolve(packet_info["dest_ip"])
        
        # protocol 1 == ICMP 6 == TCP, 17 == UDP
        if packet_info["protocol"] == "01":
            packet_info["type"] = self.str_hex_to_binary(self.read_packet(packet, ICMP["type"][0], ICMP["type"][1]))
            packet_info["code"] = self.str_hex_to_binary(self.read_packet(packet, ICMP["code"][0], ICMP["code"][1]))
            packet_info["header"] = self.read_packet(packet, ICMP["header"][0], ICMP["header"][1])
            packet_info["payload"] = self.read_packet(packet, ICMP["payload"], len(packet)*4 - ICMP["payload"])
            packet_info["bytes"] = len(packet) / 2
            
        if packet_info["protocol"] == "06" or packet_info["protocol"] == "11":
            packet_info["src_port"] = self.read_packet(packet, TCP["src_port"][0], TCP["src_port"][1])
            packet_info["dest_port"] = self.read_packet(packet, TCP["dest_port"][0], TCP["dest_port"][1])
        
        if packet_info["protocol"] == "06":
            flags_int = int(self.read_packet(packet, TCP["flag"][0], TCP["flag"][1]), 16)
            flags_int &= ~(FLAG_MASKS["URG"] | FLAG_MASKS["PSH"])
            packet_info["seq"] = self.read_packet(packet, TCP["sequence"][0], TCP["sequence"][1])
            packet_info["ack"] = self.read_packet(packet, TCP["ack"][0], TCP["ack"][1])
            packet_info["flags"] = self.int_to_hex_str(flags_int, 2)
            packet_info["payload"] = self.read_packet(packet, TCP["payload"], len(packet)*4 - TCP["payload"])
        
        if packet_info["protocol"] == "11":
            packet_info["seq"] = ""
            packet_info["ack"] = ""
            packet_info["flags"] = ""
            packet_info["payload"] = self.read_packet(packet, UDP["payload"], len(packet)*4 - UDP["payload"])

        return packet_info

    def create_reply(self, nic, dest_mac, src_mac, proto, src_ip, dest_ip, src_port, dest_port, seq, ack, flags, payload):
        
        if nic == "mgt":
            new_nic = "a8"
        elif nic == "int":
            new_nic = "a9"
        elif nic == "dmz":
            new_nic = "aa"
        else:
            new_nic = "ab"
        
        new_src_ip = self.int_to_hex_str(ip_to_int(src_ip), 8)
        new_dest_ip = self.int_to_hex_str(ip_to_int(dest_ip), 8)

        return new_nic + dest_mac + src_mac + "0800" + proto + new_src_ip + new_dest_ip + src_port + dest_port + seq + ack + flags + payload 

    def handle_TCP_UDP(self, packet):
        pkt = self.curr_packet
        
        # Allow incoming DNS traffic (port 53) on int or dmz interfaces (USE PAT) to go external
        # allow replies to return. 

        #state
        state = self.connections.state(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"])

        # Allow incoming dns traffic on int or dmz
        if pkt["ingress"] == "int" or pkt["ingress"] == "dmz":
            # dns traffic
            if pkt["dest_port"] == "0035" and pkt["egress"] == "ext":
                if state == None:
                    new_state = "established"
                    if pkt["protocol"] == "06" and pkt["flags"] == "02":
                            self.incomplete_num += 1
                            new_state = "syn_sent"

                    # set nat when its new
                    # DONT FORGET TO UNCOMMENT BELOW
                    self.pt.set_pat(pkt["src_ip"], pkt["src_port"], self.int_to_hex_str(self.pt.get_unused_port(), 4)) #"e4c9")
                    # add to conneciton table after pat translation
                    # add for egress
                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], "130.102.184.1", self.pt.get_pat_out(pkt   ["src_ip"], pkt["src_port"]), new_state)
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], new_state)
                    # self.track_connections(pkt["ingress"], pkt["egress"], pkt["protocol"], "130.102.184.1", self.pt.get_pat_out(pkt["src_ip"], 
                    #                         pkt["src_port"]), pkt["dest_ip"], pkt["dest_port"], new_state)
                elif pkt["protocol"] == "06" and state == "syn_sent" and pkt["flags"] == "10":
                    self.incomplete_num -= 1 #if dmz or int sent ack
                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], "130.102.184.1", 
                                                   self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), "established")
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], "established")
                    # self.track_connections(pkt["ingress"], pkt["egress"], pkt["protocol"], "130.102.184.1", self.pt.get_pat_out(pkt["src_ip"], 
                    #                         pkt["src_port"]), pkt["dest_ip"], pkt["dest_port"], "established")
                    
                # this is outbound so the src_mac and src_ip will be ext
                return self.create_reply(pkt["egress"], pkt["src_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], "130.102.184.1", pkt["dest_ip"],
                                         self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

        # allow incoming http and https on int
        if pkt["ingress"] == "int":
            # state = self.connections.state(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"])
            if pkt["dest_port"] == "0050" or pkt["dest_port"] == "01bb":
                new_state = "established"
                if state == None:
                    if pkt["egress"] == "ext":
                        self.pt.set_pat(pkt["src_ip"], pkt["src_port"], self.int_to_hex_str(self.pt.get_unused_port(), 4)) #"c64c")
                    if pkt["flags"] == "02":
                        self.incomplete_num += 1
                        new_state = "syn_sent"
                if state == "syn_sent" and pkt["flags"] == "10":
                    self.incomplete_num -= 1

                if pkt["egress"] == "ext":
                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], "130.102.184.1", self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), new_state)
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], new_state)
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], "130.102.184.1", pkt["dest_ip"], self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
                elif pkt["egress"] == "dmz":
                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)
                
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"],
                                                pkt["dest_port"], new_state)
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
            
            # allow ssh traffic 
            if pkt["dest_port"] == "0016":
                # allow outbound
                if pkt["egress"] == "ext":
                    if state == None and pkt["flags"] == "02":
                        self.incomplete_num += 1
                        self.pt.set_pat(pkt["src_ip"], pkt["src_port"], self.int_to_hex_str(self.pt.get_unused_port(), 4))
                        self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], "130.102.184.1", self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), "syn_sent")
                        self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], "syn_sent")
                    elif state == "syn_sent" and pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state = "established"
                        self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], "130.102.184.1", self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), "established")
                        self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], "established")
                    elif state != "established":
                        print("ALERT drop: new incoming TCP not allowed by policy")
                        return ""

                    return self.create_reply(pkt["egress"], pkt["src_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], "130.102.184.1", pkt["dest_ip"],
                                         self.pt.get_pat_out(pkt["src_ip"], pkt["src_port"]), pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
                
                if pkt["egress"] == "dmz":
                    new_state = "syn_sent"
                    if state == None:
                        if pkt["flags"] != "02":
                            print("ALERT drop: new incoming TCP not allowed by policy")
                            return ""
                        else:
                            self.incomplete_num += 1
                    elif state == "syn_sent" and pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state == "established"

                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"],
                                                pkt["dest_port"], new_state)
                    
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
                
            if pkt["src_port"] == "0016":
                if pkt["egress"] == "dmz":
                    new_state = "syn_sent"
                    if state == None:
                        if pkt["flags"] != "02":
                            print("ALERT drop: new incoming TCP not allowed by policy")
                            return ""
                        else :
                            self.incomplete_num += 1
                    elif state == "syn_sent" and pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state == "established"

                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"],
                                                pkt["dest_port"], new_state)
                    
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

        if pkt["ingress"] == "dmz":
            # http replies
            if pkt["src_port"] == "0050" or pkt["src_port"] == "01bb":
                if state == None:
                    return
                elif state == "syn_sent":
                    if pkt["flags"] == "10":
                        self.connections.add_or_update(pkt["inress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], "established")
                        self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], "established")
                if pkt["egress"] == "ext":
                    src_ip = "130.102.184.1"
                else:
                    src_ip = pkt["src_ip"]
                return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], src_ip, pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
            
            # ssh replies
            if pkt["src_port"] == "0016":
                if pkt["egress"] == "ext":
                    if state == None:
                        print("ALERT drop: new incoming TCP not allowed by policy")
                        return ""
                    src_ip = "130.102.184.1"
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], src_ip, pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

                if pkt["egress"] == "int":
                    if state == None:
                        print("ALERT drop: new incoming TCP not allowed by policy")
                        return ""
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

            if pkt["dest_port"] == "0016":
                if pkt["egress"] == "int":
                    new_state = "syn_sent"
                    if state == None:
                        if pkt["flags"] != "02":
                            print("ALERT drop: new incoming TCP not allowed by policy")
                            return ""
                        else:
                            self.incomplete_num += 1
                    elif state == "syn_sent" and pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state == "established"

                    self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)
                    self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"],
                                                pkt["dest_port"], new_state)
                    
                    return self.create_reply(pkt["egress"], pkt["dest_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])




        if pkt["ingress"] == "ext":

            # allow incoming ssh conneciton
            if pkt["dest_port"] == "0016":
                new_state = "syn_sent" # fail safe
                if state == None:
                    # new connection
                    if pkt["flags"] == "02":
                        self.incomplete_num += 1
                        new_state = "syn_sent"
                    # all ssh connections should be TCP
                    else:
                        print("ALERT drop: new incoming TCP not allowed by policy")
                        return ""
                elif state == "syn_sent":
                    if pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state = "established"
                
                pkt["egress"] = "dmz"
                pkt["dest_ip"] = "10.1.0.92"

                self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"], new_state)
                self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)
                return self.create_reply(pkt["egress"], pkt["src_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

            # reply to ssh on it
            if pkt["src_port"] == "0016" and self.pt.get_pat_in(pkt["dest_port"]) != None:
                dest_ip, dest_port = self.pt.get_pat_in_actual(pkt["dest_port"])
                egress = self.rt.resolve(dest_ip)
                pkt["egress"] = egress
                return self.create_reply(egress, pkt["dest_mac"], STR_MACS[egress], pkt["protocol"], pkt["src_ip"], dest_ip, pkt["src_port"],
                                         dest_port, pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])

            # dns traffic via pat
            # this is a reply
            # state = self.connections.state(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"])
            if pkt["src_port"] == "0035" and self.pt.get_pat_in(pkt["dest_port"]) != None:
                dest_ip, dest_port = self.pt.get_pat_in_actual(pkt["dest_port"])
                egress = self.rt.resolve(dest_ip)
                state = self.connections.state(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"])

                pkt["egress"] = egress
                pkt["dest_port"] = dest_port #check if this actually changes the packet but its python so it should lol
                pkt["dest_ip"] = dest_ip

                # if state == "syn_sent" and pkt["flags"] == "10":
                #     self.connections.add_or_update(egress, pkt["protocol"], dest_ip, dest_port, pkt["src_ip"], pkt["src_port"], "established")
                # seq, ack, flags = ""
                # if pkt["protocol"] == "06":
                #     seq, ack, flags = pkt["sequence"], pkt["ack"], pkt["flags"]
                
                return self.create_reply(egress, pkt["src_mac"], STR_MACS[egress], pkt["protocol"], pkt["src_ip"], dest_ip, pkt["src_port"], dest_port, pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
            
            # allow incoming HTTP/HTTPS on ext allow replies
            # this is new
            if pkt["dest_port"] == "0050" or pkt["dest_port"] == "01bb":
                new_state = "established" # this is a safe guard if all of the ifs fail below
                if state == None:
                    # shouldn't be syn-ack only syn or ack
                    if pkt["protocol"] == "06" and pkt["flags"] == "02":
                        self.incomplete_num += 1
                        new_state = "syn_sent"
                elif state == "syn_sent":
                    if pkt["protocol"] == "06" and pkt["flags"] == "10":
                        self.incomplete_num -= 1
                        new_state = "established"
                    else:
                        new_state = "syn_sent"

                self.connections.add_or_update(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"],
                                            pkt["dest_ip"], pkt["dest_port"], new_state)
                pkt["egress"] = "dmz"
                pkt["dest_ip"] = "10.1.0.54"
                self.connections.add_or_update(pkt["egress"], pkt["protocol"], pkt["dest_ip"], pkt["dest_port"], pkt["src_ip"], pkt["src_port"], new_state)

                return self.create_reply(pkt["egress"], pkt["src_mac"], STR_MACS[pkt["egress"]], pkt["protocol"], pkt["src_ip"],
                                         pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
            # this is a reply i think
            if pkt["src_port"] == "0050" or pkt["src_port"] == "01bb" and self.pt.get_pat_in(pkt["dest_port"]) != None:
                # dont think i have to update connections table. I could tho
                dest_ip, dest_port = self.pt.get_pat_in_actual(pkt["dest_port"])
                egress = self.rt.resolve(dest_ip)
                pkt["egress"] = egress
                return self.create_reply(egress, pkt["dest_mac"], STR_MACS[egress], pkt["protocol"], pkt["src_ip"], dest_ip, pkt["src_port"],
                                         dest_port, pkt["seq"], pkt["ack"], pkt["flags"], pkt["payload"])
                



        return ""

    """that manages all the processing: performs security checks
or routing the “packets” to the correct interfaces"""
    def process_packet(self, packet: bytes):
        # self.print_packet_info(packet)
        self.curr_packet = self.parse_packet(packet)
        pkt = self.curr_packet

        # security checks
        if not self.check_packet(packet):
            return
        
        # check for too many ping requests
        if self.non_ping >= 5:
            self.non_ping = 0
            self.ping_window = 0

        reply = ""

        # handle ICMP packets
        if pkt["protocol"] == "01":
            reply = self.create_echo_reply(packet)
        else:
            if pkt["ingress"] == "mgt":
                reply = packet
            else:
                reply = self.handle_TCP_UDP(packet)
    
        if reply == "":
            return
        
        
    
        
        self.route_packet(pkt["egress"], reply)
    

    """that performs security checks (possibly raising alerts – printed
messages); """
    def check_packet(self, packet: bytes):
        pkt = self.curr_packet

        # ICMP checks
        if pkt["protocol"] == "01":
            if pkt["type"] == 8: #and pkt["code"] == 0:
                # ICMP oversize ping
                if pkt["bytes"] > 64:
                    print("ALERT drop: oversize ping from " + pkt["src_ip"] + " (" + str(int(pkt["bytes"])) + " bytes)")
                    return False
                # deny 5 or more incoming ping requests
                if self.ping_window >= 5:
                    print("ALERT drop: ping rate limit from " + pkt["src_ip"])
                    return False
                else:
                    self.ping_window += 1
                    self.non_ping = 0
                    return True
            else:
                self.non_ping += 1
                # drop any other icmp traffic
                print("ALERT drop: ICMP type " + str(pkt["type"]) + ":" + str(pkt["code"]) + " not allowed by policy")
                return False

        # check state using pat as well
        state = self.connections.state(pkt["ingress"], pkt["protocol"], pkt["src_ip"], pkt["src_port"], pkt["dest_ip"], pkt["dest_port"])
        self.non_ping += 1
        
        if state == "established":
            return True
        
        if state == "syn_sent" and (pkt["flags"] == "12" or pkt["flags"] == "10"):
            return True
        

        # TCP checks
        if pkt["protocol"] == "06": 
            # allow incoming SSH traffic on mgt from specific IP
            if pkt["ingress"] == "mgt":
                if pkt["dest_port"] != "0016" or pkt["src_ip"] != "192.168.96.9":
                    print("ALERT drop: new incoming TCP not allowed by policy")
                    return False
                return True
            
            # if incoming
            if pkt["flags"] == "02":
                # check if over 100 open incomplete connect requests
                if self.incomplete_num >= 100:
                    print("ALERT drop: too many incomplete connections")
                    self.connections.clear_table() #need to actually clear table if its "syn_sent"
                    self.incomplete_num = 0
                    return False

                # allow incoming DNS traffic on int or dmz
                # should already be accepted if its not a syn because it should be in the connections table
                if pkt["ingress"] == "int" or pkt["ingress"] == "dmz":
                    #allow dns traffic
                    # wondering if i should check if its actually going to ext or outside and if its SYN
                    if pkt["dest_port"] == "0035" and pkt["egress"] == "ext":
                        return True

                
            if pkt["ingress"] == "int":
                # allow incoming HTTP or HTTPS int interfaces
                if pkt["dest_port"] == "0050" or pkt["dest_port"] == "01bb" and (pkt["egress"] == "ext" or pkt["egress"] == "dmz"):
                    return True
                # allow incoming ssh traffic
                if pkt["dest_port"] == "0016" and (pkt["egress"] == "ext" or pkt["egress"] == "dmz"):
                    return True


        if pkt["ingress"] == "dmz":
            if pkt["egress"] == "int" and pkt["src_ip"] == "10.1.0.92":
                return True
            

        if pkt["ingress"] == "ext":
            # drop DNS queries new inbound queries
            if pkt["src_port"] == "0035":
                #silently dropped
                # since anything in the connections table is already passed i just need to check for new incoming
                return False
            # allow ssh traffic, allow http traffic
            if pkt["dest_port"] == "0050" or pkt["dest_port"] == "01bb" or pkt["dest_port"] == "0016":
                return True

        if pkt["protocol"] == "11":
            if pkt["ingress"] == "int" or pkt["ingress"] == "dmz":
                    #allow dns traffic
                    if pkt["dest_port"] == "0035" and pkt["egress"] == "ext":
                        return True
            if pkt["ingress"] == "ext":
                if pkt["src_port"] == "0050" or pkt["src_port"] == "01bb" or pkt["src_port"]:
                    return True
                
        print("ALERT drop: new incoming TCP not allowed by policy")
        return False
                
                
            

    """ that simulates sending a packet to that
interface for sending."""
    def route_packet(self, interface: str, packet: bytes):
        if interface != "mgt":
            print("ROUTE to " + interface)
        self.ih.send_packet(interface, packet)
    
    def print_packet_info(self, packet: bytes):
        """Pretty-print key fields from the packet for debugging."""
        self.packet_num += 1
        try:
            proto = self.str_hex_to_binary(self.read_packet(packet, HEADER["protocol"][0], HEADER["protocol"][1]))
            src_ip = int_to_ip(int(self.read_packet(packet, HEADER["src_ip"][0], HEADER["src_ip"][1]), 16))
            dst_ip = int_to_ip(int(self.read_packet(packet, HEADER["dest_ip"][0], HEADER["dest_ip"][1]), 16))

            print("\n========== PACKET " + str(self.packet_num) + " ==========")
            print(f"Raw: {packet}")
            print(f"Protocol: {proto} ({'ICMP' if proto==1 else 'TCP' if proto==6 else 'UDP' if proto==17 else 'Other'})")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")

            if proto == 1:  # ICMP
                icmp_type = self.str_hex_to_binary(self.read_packet(packet, ICMP['type'][0], ICMP['type'][1]))
                icmp_code = self.str_hex_to_binary(self.read_packet(packet, ICMP['code'][0], ICMP['code'][1]))
                print(f"ICMP -> Type: {icmp_type}, Code: {icmp_code}")

            elif proto == 6:  # TCP
                src_port = self.str_hex_to_binary(self.read_packet(packet, TCP['src_port'][0], TCP['src_port'][1]))
                dst_port = self.str_hex_to_binary(self.read_packet(packet, TCP['dest_port'][0], TCP['dest_port'][1]))
                seq = self.str_hex_to_binary(self.read_packet(packet, TCP['sequence'][0], TCP['sequence'][1]))
                ack = self.str_hex_to_binary(self.read_packet(packet, TCP['ack'][0], TCP['ack'][1]))
                flags = self.str_hex_to_binary(self.read_packet(packet, TCP['flag'][0], TCP['flag'][1]))

                flag_names = [name for name, mask in FLAG_MASKS.items() if flags & mask]

                print(f"TCP -> Src Port: {src_port}, Dst Port: {dst_port}")
                print(f"Seq: {seq}, Ack: {ack}")
                print(f"Flags: {flag_names if flag_names else 'None'}")

            elif proto == 17:  # UDP
                src_port = self.str_hex_to_binary(self.read_packet(packet, UDP['src_port'][0], UDP['src_port'][1]))
                dst_port = self.str_hex_to_binary(self.read_packet(packet, UDP['dest_port'][0], UDP['dest_port'][1]))
                print(f"UDP -> Src Port: {src_port}, Dst Port: {dst_port}")

            print("============================\n")

        except Exception as e:
            print(f"[DEBUG ERROR] Could not parse packet: {e}")
    
class RouteTable:
    def __init__(self, ih):
        self.ih = ih
        self.MASKS = [0xfffff000, 0xffff0000, 0xffffff00]

    """that returns the egress interface name for the destination IP address – longest-
prefix match among local subnets, else ‘ext’ (default external)."""
    def resolve(self, ip: str):
        # get string
        # convert to binary, apply mask, convert back to ip
        binary = int(bin(ip_to_int(ip)), 2)
        for mask in self.MASKS:
            binary &= mask
            ip = int_to_ip(binary)
            interface = self.ih.IFACE_NETWORKS.get(ip)
            if (interface != None):
                return interface
        return "ext"
                
    

class Connections:

    def __init__(self):
        self.table = {}
        self.incomplete_num = 0
    """for interface (mgt/int/dmz/ext), protocol, source address and port, destina-
tion address and port, the connection state (“new”, “syn_sent”, “established”, “closed”);"""
    def add_or_update(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int, state: str):
        self.table.update({(nic, proto, src_ip, src_port, dst_ip, dst_p): state})

    """that returns the connection state (“new”, “syn_sent”, “established”, “closed”) or null if no entry is found."""
    def state(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int):

        return self.table.get((nic, proto, src_ip, src_port, dst_ip, dst_p), None)
        
    
    def get_incomplete(self):
        return self.incomplete_num
    
    def clear_table(self):
        new_table = {}
        for (nic, proto, src_ip, src_port, dst_ip, dst_p), state in self.table.items():
            if state != "syn_sent":
                new_table.update({(nic, proto, src_ip, src_port, dst_ip, dst_p): state})
        self.table = new_table

    def print_table(self):
        if not self.table:
            print("Connections table is empty.")
            return

        print("Current connections:")
        for (nic, proto, src_ip, src_port, dst_ip, dst_p), state in self.table.items():
            print(f"[{state.upper()}] {nic} | Proto {proto} | "
                  f"{src_ip}:{src_port} -> {dst_ip}:{dst_p}")


def run_appliance(cap_file) -> None:
    ih = InterfaceHandler(cap_file)
    pe = PacketEngine(ih)

    if not cap_file:
        print("Listening...")
 
        def handle(pkt):
            try:
                iface = pkt.sniffed_on
                print(iface)
                logical_iface = INTERFACE_MAP.get(iface, "ext") # if iface is unknown its treated as external
                hex_packet = ih.scapy_to_format(pkt)
                if hex_packet:
                    pe.process_packet(hex_packet)
            except Exception as e:
                print(f"Error processing packet: {e}")
    
        sniff( prn=handle, store=False)
    else: 
        while True:
            raw = ih.next_packet()
            if raw is None:
                break
            pe.process_packet(raw)

def main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        iface = sys.argv[2] if len (sys.argv) > 2 else "enp0s1"
        run_appliance(None)
    else: run_appliance("traffic.spcap")

if __name__ == "__main__":
    main()
