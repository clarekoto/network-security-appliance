from scapy.all import IP, TCP, UDP, ICMP, send
import time
import sys

# ---------------------- Interface mapping ----------------------

INT_SRC  = "192.168.64.1"   # Mac side of int  (bridge100)
EXT_SRC  = "192.168.56.1"   # Mac side of ext  (bridge101)
DMZ_SRC  = "192.168.57.1"   # Mac side of dmz  (bridge102)
MGT_SRC  = "192.168.58.1"   # Mac side of mgt  (bridge103)

INT_DST  = "192.168.64.2"   # VM enp0s1 (int)
EXT_DST  = "192.168.56.2"   # VM enp0s2 (ext)
DMZ_DST  = "192.168.57.2"   # VM enp0s3 (dmz)
MGT_DST  = "192.168.58.2"   # VM enp0s4 (mgt)

INT_IFACE = "bridge100"
EXT_IFACE = "bridge101"
DMZ_IFACE = "bridge102"
MGT_IFACE = "bridge103"

# ---------------------- Helpers ----------------------

def check(expected):
    answer = input(f"Expected: {expected}\nDid the alert appear? (y/n): ")
    print("PASS" if answer.strip().lower() == "y" else "FAIL")

def run_test(name, pkt, iface, expected):
    print(f"\n--- {name} ---")
    print(f"Sending to {iface}...")
    send(pkt, verbose=False)
    time.sleep(1)
    check(expected)



def test1():
    # should trigger: ALERT drop: oversize ping from x.x.x.x (114 bytes)
    run_test(
        "Oversize ping",
        IP(src=EXT_SRC, dst=EXT_DST)/ICMP()/("X"*100),
        EXT_IFACE,
        "ALERT drop: oversize ping"
    )


def test2():
    # send 6 pings in a row to exceed the 5 ping window
    # should trigger: ALERT drop: ping rate limit from x.x.x.x on the 6th
    print(f"\n--- Ping rate limit ---")
    print(f"Sending on {EXT_IFACE}...")
    for _ in range(6):
        send(IP(src=EXT_SRC, dst=EXT_DST)/ICMP(), verbose=False)
        time.sleep(0.1)
    time.sleep(1)
    check("first 5 allowed, 6th should trigger rate limit alert")


def test3():
    # should trigger: ALERT drop: ICMP type 3:0 not allowed by policy
    run_test(
        "Blocked ICMP type (destination unreachable)",
        IP(src=EXT_SRC, dst=EXT_DST)/ICMP(type=3, code=0),
        EXT_IFACE,
        "ALERT drop: ICMP type 3:0 not allowed by policy"
    )


def test4():
    # should trigger: ALERT drop: too many incomplete connections
    print(f"\n--- SYN flood (sending 110 SYN packets) ---")
    print(f"Sending on {EXT_IFACE}...")
    for i in range(101):
        send(IP(src=EXT_SRC, dst=EXT_DST)/TCP(sport=1024+i, dport=80, flags="S"), verbose=False)
    time.sleep(1)
    check("ALERT drop: too many incomplete connections")


def test5():
    # mgt only allows SSH from 192.168.96.9, anything else should be dropped
    run_test(
        "Unauthorised source SSH",
        IP(src="1.2.3.4", dst=MGT_DST)/TCP(dport=22, flags="S"),
        MGT_IFACE,
        "ALERT drop: new incoming TCP not allowed by policy"
    )


def test6():
    run_test(
        "Connection on blocked port",
        IP(src=EXT_SRC, dst=EXT_DST)/TCP(dport=9999, flags="S"),
        EXT_IFACE,
        "ALERT drop: new incoming TCP not allowed by policy"
    )


def test7():
    run_test(
        "UDP on blocked port",
        IP(src=EXT_SRC, dst=EXT_DST)/UDP(dport=9999),
        EXT_IFACE,
        "ALERT drop: new incoming TCP not allowed by policy"
    )


def test8():
    # should be silently dropped with no alert
    run_test(
        "Inbound DNS query",
        IP(src=EXT_SRC, dst=EXT_DST)/UDP(sport=12345, dport=53),
        EXT_IFACE,
        "Silent drop - no alert expected"
    )


TESTS = {
    "1": test1,
    "2": test2,
    "3": test3,
    "4": test4,
    "5": test5,
    "6": test6,
    "7": test7,
    "8": test8,
}


def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg in TESTS:
                TESTS[arg]()
            else:
                print(f"Unknown test: {arg}. Valid tests are 1-8.")
    else:
        for test in TESTS.values():
            test()
        print("\n--- all tests sent ---")


if __name__ == "__main__":
    main()
