#!/usr/bin/env python3

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

GREEN  = "\033[92m"
DARK_GREEN = "\033[32m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"


SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def clear():
    print("\033[2J\033[H", end="")


def banner():
    print(f"""
{GREEN}{BOLD}
 ███╗   ██╗███████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

        N E T W O R K   S C A N N E R
{RESET}{DIM}
        [ TCP RECON ENGINE ]
        [ AUTHORIZED USE ONLY ]
{RESET}
""")


def parse_ports(value):
    ports = set()

    for part in value.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(int, part.split("-", 1))

            if not (1 <= start <= end <= 65535):
                raise ValueError("Invalid port range")

            ports.update(range(start, end + 1))

        else:
            port = int(part)

            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535")

            ports.add(port)

    return sorted(ports)


def scan_port(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if sock.connect_ex((ip, port)) == 0:
            return port

    except OSError:
        pass

    finally:
        sock.close()

    return None


def service(port):
    return SERVICES.get(port, "UNKNOWN")


def progress(current, total, width=35):
    percent = current / total
    filled = int(width * percent)

    bar = (
        GREEN + "█" * filled +
        DARK_GREEN + "░" * (width - filled) +
        RESET
    )

    return f"[{bar}] {percent * 100:6.2f}%"


def main():

    parser = argparse.ArgumentParser(
        description="NEONSCAN TCP reconnaissance tool"
    )

    parser.add_argument(
        "target",
        help="Target IP or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Ports: 22,80,443 or 1-1000"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=200,
        help="Parallel connections"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout"
    )

    args = parser.parse_args()

    clear()
    banner()

    # Resolve target
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{RED}[!] TARGET RESOLUTION FAILED{RESET}")
        sys.exit(1)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"{RED}[!] {e}{RESET}")
        sys.exit(1)

    print(
        f"{CYAN}{BOLD}"
        f"┌─[ TARGET ]─────────────────────────────────────┐"
        f"{RESET}"
    )

    print(f"│ {WHITE}HOST     :{RESET} {args.target}")
    print(f"│ {WHITE}IP       :{RESET} {ip}")
    print(f"│ {WHITE}PORTS    :{RESET} {len(ports)}")
    print(f"│ {WHITE}THREADS  :{RESET} {args.workers}")
    print(f"│ {WHITE}TIMEOUT  :{RESET} {args.timeout}s")

    print(
        f"{CYAN}{BOLD}"
        f"└─────────────────────────────────────────────────┘"
        f"{RESET}\n"
    )

    print(
        f"{DARK_GREEN}[+] Initializing TCP engine...{RESET}"
    )

    time.sleep(0.3)

    print(
        f"{DARK_GREEN}[+] Target acquired: {ip}{RESET}"
    )

    time.sleep(0.2)

    print(
        f"{DARK_GREEN}[+] Starting reconnaissance...{RESET}\n"
    )

    start = time.perf_counter()

    open_ports = []

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip,
                port,
                args.timeout
            ): port

            for port in ports
        }

        completed = 0

        for future in as_completed(futures):

            completed += 1

            port = future.result()

            if port is not None:

                open_ports.append(port)

                print(
                    f"\r{GREEN}{BOLD}"
                    f"[+] OPEN"
                    f"{RESET} "
                    f"{WHITE}{port:5}"
                    f"{RESET} │ "
                    f"{CYAN}{service(port)}"
                    f"{RESET}"
                )

            # Live progress
            if completed % 25 == 0 or completed == len(ports):

                print(
                    f"\r{DIM}"
                    f"SCAN {progress(completed, len(ports))}"
                    f"{RESET}",
                    end="",
                    flush=True
                )

    elapsed = time.perf_counter() - start

    open_ports.sort()

    print("\n")

    # Results
    print(
        f"{GREEN}{BOLD}"
        "╔══════════════════════════════════════════════════╗"
        "\n"
        "║                 SCAN COMPLETE                   ║"
        "\n"
        "╚══════════════════════════════════════════════════╝"
        f"{RESET}"
    )

    print()

    if open_ports:

        print(
            f"{GREEN}{BOLD}"
            " PORT       STATE       SERVICE"
            f"{RESET}"
        )

        print(
            f"{DARK_GREEN}"
            " ─────────────────────────────────"
            f"{RESET}"
        )

        for port in open_ports:

            print(
                f" {GREEN}{port:<10}{RESET}"
                f"{GREEN}OPEN{RESET}        "
                f"{CYAN}{service(port)}{RESET}"
            )

    else:

        print(
            f"{RED}[!] No open TCP ports detected.{RESET}"
        )

    print()

    print(
        f"{GRAY}"
        f"──────────────────────────────────────────────────"
        f"{RESET}"
    )

    print(
        f"{WHITE}TARGET   {RESET} {ip}"
    )

    print(
        f"{WHITE}SCANNED  {RESET} {len(ports)} ports"
    )

    print(
        f"{WHITE}OPEN     {RESET} "
        f"{GREEN}{len(open_ports)}{RESET}"
    )

    print(
        f"{WHITE}TIME     {RESET} {elapsed:.2f}s"
    )

    print(
        f"{GRAY}"
        f"──────────────────────────────────────────────────"
        f"{RESET}"
    )

    print(
        f"\n{DARK_GREEN}"
        "[ NEONSCAN ] connection terminated."
        f"{RESET}\n"
    )


if __name__ == "__main__":
    main()
