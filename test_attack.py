from scapy.all import IP, TCP, UDP, ICMP, send
import time

TARGET = "192.168.64.2"  # your VM's IP

def test(name, pkt, expected):
    print(f"\n--- {name} ---")
    print(f"Expected: {expected}")
    print(f"Sending...")
    send(pkt, verbose=False)
    time.sleep(1)  # give firewall time to process

# test 1 - oversize ping
# should trigger: ALERT drop: oversize ping from x.x.x.x (114 bytes)
test(
    "Oversize ping",
    IP(dst=TARGET)/ICMP()/("X"*100),
    "ALERT drop: oversize ping"
)

# test 2 - ping rate limit
# should trigger: ALERT drop: ping rate limit from x.x.x.x
# send 6 pings in a row to exceed the 5 ping window
test(
    "Ping rate limit",
    IP(dst=TARGET)/ICMP(),
    "first 5 allowed, 6th should trigger rate limit alert"
)
for i in range(5):
    send(IP(dst=TARGET)/ICMP(), verbose=False)
    time.sleep(0.1)

# test 3 - blocked ICMP type
# should trigger: ALERT drop: ICMP type 3:0 not allowed by policy
test(
    "Blocked ICMP type (destination unreachable)",
    IP(dst=TARGET)/ICMP(type=3, code=0),
    "ALERT drop: ICMP type 3:0 not allowed by policy"
)

# test 4 - SYN flood / too many incomplete connections
# should trigger: ALERT drop: too many incomplete connections
print(f"\n--- SYN flood (sending 110 SYN packets) ---")
print(f"Expected: ALERT drop: too many incomplete connections")
for i in range(110):
    send(IP(dst=TARGET)/TCP(dport=80, flags="S"), verbose=False)
time.sleep(1)

# test 5 - unauthorised SSH on mgt
# mgt only allows SSH from 192.168.96.9
# anything else should be dropped
test(
    "Unauthorised source SSH",
    IP(src="1.2.3.4", dst=TARGET)/TCP(dport=22, flags="S"),
    "ALERT drop: new incoming TCP not allowed by policy"
)

# test 6 - random port no policy allows
test(
    "Connection on blocked port",
    IP(dst=TARGET)/TCP(dport=9999, flags="S"),
    "ALERT drop: new incoming TCP not allowed by policy"
)

# test 7 - UDP on blocked port
test(
    "UDP on blocked port",
    IP(dst=TARGET)/UDP(dport=9999),
    "ALERT drop: new incoming TCP not allowed by policy"
)

# test 8 - inbound DNS query on ext (should be silently dropped)
test(
    "Inbound DNS query",
    IP(dst=TARGET)/UDP(sport=12345, dport=53),
    "Silent drop - no alert expected"
)

print("\n--- all tests sent ---")
print("check your firewall terminal for alerts")