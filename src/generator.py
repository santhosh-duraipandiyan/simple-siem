"""
generator.py — SIMULATED LOG SOURCES (the "devices" on the network).

This is NOT one of the three SIEM stages. It stands in for the real servers,
firewalls, and web servers that would normally send logs. It emits raw log
lines in THREE DIFFERENT formats so that the normalizer has real work to do:

  - auth      : Linux SSH syslog lines
  - firewall  : firewall DENY/ALLOW lines
  - web       : Apache-style HTTP access lines

Most traffic is harmless "noise". Every so often the generator launches a
scripted ATTACK (SSH brute force, port scan, or web app scan) so the
correlator reliably produces alerts for students to see.
"""
import random
import time

from common import connect, push, Q_RAW, now_iso, banner, CYAN, DIM, RESET

# ---- Pools of fake-but-realistic values -------------------------------------
NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve"]
INTERNAL_HOSTS = ["web01", "web02", "db01", "app01"]
NORMAL_IPS = ["10.0.0." + str(i) for i in range(10, 40)]
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "185.220.101.7", "45.83.66.12"]
WEB_PATHS = ["/", "/index.html", "/about", "/contact", "/products", "/login"]
ATTACK_PATHS = ["/admin.php", "/wp-login.php", "/../../etc/passwd",
                "/index.php?id=1' OR '1'='1", "/shell.php"]
BAD_AGENTS = ["sqlmap/1.5.2", "Nikto/2.1.6", "() { :; }; /bin/bash", "curl/7.68"]
GOOD_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]


def syslog_ts():
    return time.strftime("%b %d %H:%M:%S", time.gmtime())


# ---- Raw line builders (one per source format) ------------------------------
def auth_line(user, ip, ok):
    host = random.choice(INTERNAL_HOSTS)
    pid = random.randint(1000, 9999)
    if ok:
        return (f"{syslog_ts()} {host} sshd[{pid}]: Accepted password for "
                f"{user} from {ip} port {random.randint(30000, 60000)} ssh2")
    return (f"{syslog_ts()} {host} sshd[{pid}]: Failed password for "
            f"{user} from {ip} port {random.randint(30000, 60000)} ssh2")


def firewall_line(ip, dport, deny):
    action = "DENY" if deny else "ALLOW"
    dst = "10.0.0." + str(random.randint(2, 9))
    return (f"{syslog_ts()} FW: {action} TCP {ip}:{random.randint(40000, 65000)} "
            f"-> {dst}:{dport} len={random.randint(40, 1500)}")


def web_line(ip, path, agent, status):
    ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
    method = "POST" if "login" in path or "php" in path else "GET"
    return (f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} '
            f'{random.randint(200, 5000)} "-" "{agent}"')


def emit(r, source, line):
    """Wrap a raw line with just enough metadata for the collector."""
    push(r, Q_RAW, {"source": source, "line": line, "sent_at": now_iso()})
    print(f"{DIM}[generator] {source:8s} | {line}{RESET}", flush=True)


# ---- Normal background traffic ----------------------------------------------
def emit_noise(r):
    roll = random.random()
    if roll < 0.4:
        emit(r, "auth", auth_line(random.choice(NORMAL_USERS),
                                  random.choice(NORMAL_IPS), ok=random.random() < 0.85))
    elif roll < 0.7:
        emit(r, "firewall", firewall_line(random.choice(NORMAL_IPS),
                                          random.choice([80, 443, 22, 3306]),
                                          deny=random.random() < 0.2))
    else:
        emit(r, "web", web_line(random.choice(NORMAL_IPS),
                                random.choice(WEB_PATHS),
                                random.choice(GOOD_AGENTS), 200))


# ---- Scripted attacks (make alerts fire) ------------------------------------
def attack_ssh_bruteforce(r):
    ip = random.choice(ATTACKER_IPS)
    print(f"{CYAN}[generator] >> launching SSH brute-force from {ip}{RESET}", flush=True)
    for _ in range(random.randint(8, 12)):
        emit(r, "auth", auth_line("root", ip, ok=False))
        time.sleep(0.2)
    # Sometimes the attacker finally succeeds — a much scarier event.
    if random.random() < 0.5:
        emit(r, "auth", auth_line("root", ip, ok=True))


def attack_port_scan(r):
    ip = random.choice(ATTACKER_IPS)
    print(f"{CYAN}[generator] >> launching port scan from {ip}{RESET}", flush=True)
    for dport in random.sample(range(1, 9000), random.randint(12, 18)):
        emit(r, "firewall", firewall_line(ip, dport, deny=True))
        time.sleep(0.1)


def attack_web_scan(r):
    ip = random.choice(ATTACKER_IPS)
    print(f"{CYAN}[generator] >> launching web app scan from {ip}{RESET}", flush=True)
    for _ in range(random.randint(6, 10)):
        emit(r, "web", web_line(ip, random.choice(ATTACK_PATHS),
                                random.choice(BAD_AGENTS),
                                random.choice([404, 403, 500, 200])))
        time.sleep(0.2)


def main():
    r = connect()
    banner(CYAN, "SIMULATED LOG SOURCES (generator)")
    attacks = [attack_ssh_bruteforce, attack_port_scan, attack_web_scan]
    ticks = 0
    while True:
        emit_noise(r)
        ticks += 1
        # Roughly every ~15 noise events, fire one scripted attack.
        if ticks % 15 == 0:
            random.choice(attacks)(r)
        time.sleep(random.uniform(0.4, 1.0))


if __name__ == "__main__":
    main()
