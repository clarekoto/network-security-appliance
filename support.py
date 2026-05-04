import re
import ipaddress

# ---------------------- Constants ----------------------

IFACE_CODES = {"mgt": 0, "int": 1, "dmz": 2, "ext": 3}

# Physical interface names
INT_PHYS = "enp0s1"
EXT_PHYS = "enp0s2"
DMZ_PHYS = "enp0s3"
MGT_PHYS = "enp0s4"

# Subnet prefixes
INT_SUBNET      = "192.168.64"
EXT_SUBNET      = "192.168.56"
DMZ_SUBNET      = "192.168.57"
MGT_SUBNET      = "192.168.58"
DMZ_HOST_SUBNET = "10.1.0"

# Map physical interface names to logical interface names
INTERFACE_MAP = {
    INT_PHYS: "int",
    EXT_PHYS: "ext",
    DMZ_PHYS: "dmz",
    MGT_PHYS: "mgt",
}

# Reverse map: logical name → physical interface name, used when sending packets
IFACE_NAMES = {
    "int": INT_PHYS,
    "ext": EXT_PHYS,
    "dmz": DMZ_PHYS,
    "mgt": MGT_PHYS,
}

# Map network addresses to the logical interface that owns that subnet
IFACE_NETWORKS = {
    f"{INT_SUBNET}.0":      "int",
    f"{EXT_SUBNET}.0":      "ext",
    f"{DMZ_SUBNET}.0":      "dmz",
    f"{DMZ_HOST_SUBNET}.0": "dmz",
    f"{MGT_SUBNET}.0":      "mgt",
}

# Interface addresses
INT_SRC  = f"{INT_SUBNET}.1"
EXT_SRC  = f"{EXT_SUBNET}.1"
DMZ_SRC  = f"{DMZ_SUBNET}.1"
MGT_SRC  = f"{MGT_SUBNET}.1"

INT_DST  = f"{INT_SUBNET}.2"
EXT_DST  = f"{EXT_SUBNET}.2"
DMZ_DST  = f"{DMZ_SUBNET}.2"
MGT_DST  = f"{MGT_SUBNET}.2"

INT_IFACE = "bridge100"
EXT_IFACE = "bridge101"
DMZ_IFACE = "bridge102"
MGT_IFACE = "bridge103"


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))

def int_to_ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))

def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))

def validate_mac_string(mac: str) -> None:
    if not isinstance(mac, str):
        raise ValueError("MAC address must be a string")
    pattern = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
    if not pattern.match(mac.strip()):
        raise ValueError("MAC must be in format aa:bb:cc:dd:ee:ff (lowercase hex)")

def validate_ipv4(ip: str) -> None:
    try:
        ipaddress.IPv4Address(ip)
    except Exception as e:
        raise ValueError(f"Invalid IPv4 address: {ip}") from e
