import re
import ipaddress

# ---------------------- Constants ----------------------

IFACE_CODES = {"mgt": 0, "int": 1, "dmz": 2, "ext": 3}
IFACE_NAMES = {v: k for k, v in IFACE_CODES.items()}

# ------------------- Utility helpers -------------------

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
