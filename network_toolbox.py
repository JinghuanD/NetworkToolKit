#!/usr/bin/env python3


import socket
import struct
import time
import threading
import ipaddress
from queue import Queue


# ─────────────────────────────────────────────
#  PART A – Threaded Port Scanner
# ─────────────────────────────────────────────

MAX_THREADS = 5
results_lock = threading.Lock()
scan_results = []   # list of (ip_str, port) tuples


def scan_port(ip: str, port: int):
    """Try to TCP-connect to ip:port; record if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            with results_lock:
                scan_results.append((ip, port))
    except Exception:
        pass


def worker(task_queue: Queue):
    """Thread worker: pull (ip, port) tasks until queue is empty."""
    while True:
        try:
            ip, port = task_queue.get_nowait()
        except Exception:
            break
        scan_port(ip, port)
        task_queue.task_done()


def port_scanner():
    global scan_results
    scan_results = []

    # ── Collect inputs ──────────────────────────────────────────
    start_ip_str = input("  Enter starting IP Address: ").strip()
    try:
        start_ip = ipaddress.IPv4Address(start_ip_str)
    except ValueError:
        print("  Invalid IP address.")
        return

    end_ip_str = input("  Enter ending IP Address (leave blank to scan only start): ").strip()
    if end_ip_str == "":
        end_ip = start_ip
    else:
        try:
            end_ip = ipaddress.IPv4Address(end_ip_str)
        except ValueError:
            print("  Invalid ending IP address.")
            return

    if int(end_ip) < int(start_ip):
        print("  Ending IP must be >= starting IP.")
        return

    start_port_str = input("  Enter starting TCP port (0 = all ports): ").strip()
    try:
        start_port = int(start_port_str)
    except ValueError:
        print("  Invalid port number.")
        return

    if start_port == 0:
        port_range = range(0, 65536)
    else:
        end_port_str = input("  Enter ending TCP port (leave blank to scan only start port): ").strip()
        if end_port_str == "":
            end_port = start_port
        else:
            try:
                end_port = int(end_port_str)
            except ValueError:
                print("  Invalid port number.")
                return
        if end_port < start_port:
            print("  Ending port must be >= starting port.")
            return
        port_range = range(start_port, end_port + 1)

    # ── Build task queue ────────────────────────────────────────
    task_queue: Queue = Queue()
    current = int(start_ip)
    while current <= int(end_ip):
        ip_str = str(ipaddress.IPv4Address(current))
        for port in port_range:
            task_queue.put((ip_str, port))
        current += 1

    total_tasks = task_queue.qsize()
    print(f"\n  Scanning {total_tasks:,} target(s) using up to {MAX_THREADS} thread(s)…\n")

    # ── Launch threads ──────────────────────────────────────────
    threads = []
    for _ in range(min(MAX_THREADS, total_tasks or 1)):
        t = threading.Thread(target=worker, args=(task_queue,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    # ── Print results sorted by IP then port ────────────────────
    if not scan_results:
        print("  No open ports found.")
        return

    scan_results.sort(key=lambda x: (list(map(int, x[0].split("."))), x[1]))
    for ip_str, port in scan_results:
        print(f"  IP Address: {ip_str}, Port {port} is open")


# ─────────────────────────────────────────────
#  PART B – Unthreaded UDP Ping
# ─────────────────────────────────────────────

UDP_PORT   = 33434   # classic traceroute-style UDP port
PING_COUNT = 5
TIMEOUT    = 2       # seconds

# Payload
_NAME      = b"Jinghuan Ding"                   
PAYLOAD    = (_NAME + b"\x00" * 56)[:56]        


def udp_ping():
    target_ip = input("  Enter target IP Address: ").strip()
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print("  Invalid IP address.")
        return

    print(f"\n  Pinging {target_ip} with {len(PAYLOAD)} bytes of data:")

    ttl_values   = []
    rtt_values   = []
    sent         = 0
    received     = 0

    # Raw ICMP socket to catch "port unreachable" replies
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(TIMEOUT)
    except PermissionError:
        print("  Error: raw socket requires root/admin privileges.")
        return

    for _ in range(PING_COUNT):
        # UDP send socket
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)

        sent += 1
        t_start = time.time()

        try:
            send_sock.sendto(PAYLOAD, (target_ip, UDP_PORT))
            data, addr = recv_sock.recvfrom(1024)
            t_end = time.time()

            rtt_ms = int((t_end - t_start) * 1000)

            # Parse TTL from IP header (byte 8 of the raw packet)
            ttl = data[8] if len(data) >= 9 else 0

            # ICMP type 3 = Destination Unreachable (port unreachable = host is alive)
            # ICMP type 0 = Echo Reply (shouldn't happen here but accept it too)
            icmp_type = data[20] if len(data) >= 21 else -1

            if icmp_type in (0, 3):
                received += 1
                rtt_values.append(rtt_ms)
                ttl_values.append(ttl)
                print(f"  Reply from {addr[0]}: bytes={len(PAYLOAD)} time={rtt_ms}ms TTL={ttl}")
            else:
                print("  Request timed out.")

        except socket.timeout:
            print("  Request timed out.")
        finally:
            send_sock.close()

        time.sleep(0.2)   # brief pause between pings

    recv_sock.close()

    # ── Statistics ──────────────────────────────────────────────
    lost       = sent - received
    loss_pct   = int((lost / sent) * 100) if sent else 0

    print(f"\n  Ping statistics for {target_ip}:")
    print(f"  Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_pct}% loss)")

    if rtt_values:
        print(f"  Approximate round trip times in milli-seconds:")
        print(f"  Minimum = {min(rtt_values)}ms, Maximum = {max(rtt_values)}ms, "
              f"Average = {sum(rtt_values) // len(rtt_values)}ms")


# ─────────────────────────────────────────────
#  PART C – ICMP Traceroute
# ─────────────────────────────────────────────

def checksum(data: bytes) -> int:
    """Compute Internet checksum."""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_icmp_packet(seq: int) -> bytes:
    """Build a raw ICMP Echo Request packet."""
    icmp_type = 8    # Echo Request
    code      = 0
    chksum    = 0
    pid       = threading.get_ident() & 0xFFFF
    header    = struct.pack("bbHHh", icmp_type, code, chksum, pid, seq)
    data      = b"traceroute"
    chksum    = checksum(header + data)
    header    = struct.pack("bbHHh", icmp_type, code, chksum, pid, seq)
    return header + data


def icmp_traceroute():
    target = input("  Enter target hostname or IP: ").strip()
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("  Cannot resolve hostname.")
        return

    max_hops  = 30
    timeout   = 2
    print(f"\n  Traceroute to {target} ({target_ip}), max {max_hops} hops:\n")

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("  Error: raw socket requires root/admin privileges.")
        return

    recv_sock.settimeout(timeout)

    for ttl in range(1, max_hops + 1):
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        packet = build_icmp_packet(ttl)
        t_start = time.time()
        send_sock.sendto(packet, (target_ip, 0))
        send_sock.close()

        try:
            data, addr = recv_sock.recvfrom(1024)
            t_end  = time.time()
            rtt_ms = int((t_end - t_start) * 1000)

            hop_ip = addr[0]
            try:
                hop_name = socket.gethostbyaddr(hop_ip)[0]
            except socket.herror:
                hop_name = hop_ip

            icmp_type = data[20] if len(data) >= 21 else -1
            print(f"  {ttl:>3}  {rtt_ms:>5}ms  {hop_name} ({hop_ip})")

            if hop_ip == target_ip or icmp_type == 0:   # 0 = Echo Reply → destination reached
                print(f"\n  Trace complete.")
                break

        except socket.timeout:
            print(f"  {ttl:>3}  {'*':>5}     Request timed out.")

    recv_sock.close()

# ─────────────────────────────────────────────
#  MENU OPTION 4 – ICMP Ping
# ─────────────────────────────────────────────

ICMP_PING_COUNT = 4
ICMP_TIMEOUT    = 2


def icmp_ping():
    target = input("  Enter target hostname or IP: ").strip()
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("  Cannot resolve hostname.")
        return

    # Build a fixed 56-byte payload (matches UDP ping convention)
    icmp_payload = b"icmpping" + b"\x00" * 48   # 8 + 48 = 56 bytes

    print(f"\n  Pinging {target_ip} with {len(icmp_payload)} bytes of data:\n")

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw_sock.settimeout(ICMP_TIMEOUT)
    except PermissionError:
        print("  Error: raw socket requires root/admin privileges.")
        return

    pid        = threading.get_ident() & 0xFFFF
    sent       = 0
    received   = 0
    rtt_values = []

    for seq in range(1, ICMP_PING_COUNT + 1):
        # Build ICMP Echo Request
        icmp_type = 8
        code      = 0
        chksum    = 0
        header    = struct.pack("bbHHh", icmp_type, code, chksum, pid, seq)
        chksum    = checksum(header + icmp_payload)
        header    = struct.pack("bbHHh", icmp_type, code, chksum, pid, seq)
        packet    = header + icmp_payload

        sent += 1
        t_start = time.time()
        raw_sock.sendto(packet, (target_ip, 0))

        try:
            while True:
                data, addr = raw_sock.recvfrom(1024)
                t_end = time.time()

                # Verify it's an Echo Reply (type=0) for our pid
                if len(data) >= 28:
                    resp_type = data[20]
                    resp_pid  = struct.unpack("H", data[24:26])[0]
                    if resp_type == 0 and resp_pid == pid:
                        rtt_ms = int((t_end - t_start) * 1000)
                        ttl    = data[8]
                        received += 1
                        rtt_values.append(rtt_ms)
                        print(f"  Reply from {addr[0]}: bytes={len(icmp_payload)} "
                              f"time={rtt_ms}ms TTL={ttl}")
                        break
        except socket.timeout:
            print("  Request timed out.")

        time.sleep(0.2)

    raw_sock.close()

    # ── Statistics ──────────────────────────────────────────────
    lost     = sent - received
    loss_pct = int((lost / sent) * 100) if sent else 0

    print(f"\n  Ping statistics for {target_ip}:")
    print(f"  Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_pct}% loss)")

    if rtt_values:
        print("  Approximate round trip times in milli-seconds:")
        print(f"  Minimum = {min(rtt_values)}ms, Maximum = {max(rtt_values)}ms, "
              f"Average = {sum(rtt_values) // len(rtt_values)}ms")


# ─────────────────────────────────────────────
#  MENU OPTION 5 – Traceroute
# ─────────────────────────────────────────────

def traceroute():
    target = input("  Enter target hostname or IP: ").strip()
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("  Cannot resolve hostname.")
        return

    max_hops = 30
    timeout  = 2
    probes   = 3      # send 3 probes per TTL (like real traceroute)

    print(f"\n  Traceroute to {target} ({target_ip}), {max_hops} hops max:\n")
    print(f"  {'Hop':>3}  {'1st':>7}  {'2nd':>7}  {'3rd':>7}  Host")
    print(f"  {'─'*3}  {'─'*7}  {'─'*7}  {'─'*7}  {'─'*30}")

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        print("  Error: raw socket requires root/admin privileges.")
        return

    pid = threading.get_ident() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        hop_ip    = None
        hop_rtts  = []

        for probe in range(probes):
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            seq    = ttl * 10 + probe
            packet = build_icmp_packet(seq)

            t_start = time.time()
            send_sock.sendto(packet, (target_ip, 0))
            send_sock.close()

            try:
                while True:
                    data, addr = recv_sock.recvfrom(1024)
                    t_end  = time.time()
                    rtt_ms = int((t_end - t_start) * 1000)

                    icmp_type = data[20] if len(data) >= 21 else -1
                    # Accept Time Exceeded (11) or Echo Reply (0)
                    if icmp_type in (0, 11):
                        hop_ip = addr[0]
                        hop_rtts.append(f"{rtt_ms}ms")
                        break
            except socket.timeout:
                hop_rtts.append("  *  ")

        # Resolve hostname
        if hop_ip:
            try:
                hop_name = socket.gethostbyaddr(hop_ip)[0]
            except socket.herror:
                hop_name = hop_ip
            host_field = f"{hop_name} ({hop_ip})"
        else:
            host_field = "Request timed out."

        # Pad rtt columns to 3 entries
        while len(hop_rtts) < probes:
            hop_rtts.append("  *  ")

        print(f"  {ttl:>3}  {hop_rtts[0]:>7}  {hop_rtts[1]:>7}  {hop_rtts[2]:>7}  {host_field}")

        # Stop if we've reached the destination
        if hop_ip == target_ip:
            print(f"\n  Trace complete.")
            break

    recv_sock.close()
# ─────────────────────────────────────────────
#  Main Menu
# ─────────────────────────────────────────────

MENU = """
╔══════════════════════════════════════════╗
║       MINT712 Network Utility Tool       ║
╠══════════════════════════════════════════╣
║  1. Port Scanner                         ║
║  2. UDP Ping                             ║
║  3. ICMP Traceroute (UDP-based)          ║
║  4. ICMP Ping                            ║
║  5. Traceroute (ICMP Echo)               ║
║  0. Exit                                 ║
╚══════════════════════════════════════════╝
"""



def main():
    while True:
        print(MENU)
        choice = input("  Select an option: ").strip()

        if choice == "1":
            print("\n── Port Scanner ──────────────────────────\n")
            port_scanner()

        elif choice == "2":
            print("\n── UDP Ping ───────────────────────────────\n")
            udp_ping()

        elif choice == "3":
            print("\n── ICMP Traceroute ────────────────────────\n")
            icmp_traceroute()
        elif choice == "4":
            print("\n── ICMP Ping ──────────────────────────────\n")
            icmp_ping()

        elif choice == "5":
            print("\n── Traceroute (ICMP Echo) ─────────────────\n")
            traceroute()

        elif choice in ("4", "5"):
            print(f"\n  Option {choice} is currently Under Development. Returning to main menu…")

        elif choice == "0":
            print("\n  Exit\n")
            break

        else:
            print("\n  Invalid option. Please try again.")

        input("\n  Press Enter to return to the menu")


if __name__ == "__main__":
    main()
