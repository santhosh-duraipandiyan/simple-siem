"""
correlator.py — STAGE 3 of 3: CORRELATION & ALERTING.

Job: look across MANY normalized events over time and decide when something
looks malicious. A single failed login is normal; ten failed logins from the
same IP in 30 seconds is a brute-force attack. That "many events together mean
something" logic is called CORRELATION.

We keep a short sliding-window history per source IP in memory and run a small
set of detection rules on every incoming event:

  RULE 1  SSH brute force        many failed logins from one IP
  RULE 2  Brute-force SUCCESS    a success right after many failures (critical)
  RULE 3  Port scan              one IP blocked on many different ports
  RULE 4  Web application scan   suspicious paths / attack tools in web logs

Each rule that trips prints a clearly formatted ALERT box.
"""
import time
from collections import defaultdict, deque

from common import (connect, pop, Q_EVENTS, banner,
                    MAGENTA, RED, YELLOW, GREEN, WHITE, BG_RED,
                    BOLD, DIM, RESET)

# ---- Tunable thresholds (kept obvious for teaching) -------------------------
WINDOW_SECONDS = 30          # how far back "recent" events count
SSH_FAIL_THRESHOLD = 5       # failed SSH logins -> brute force
SCAN_PORT_THRESHOLD = 10     # distinct blocked ports -> port scan
WEB_HIT_THRESHOLD = 4        # suspicious web requests -> app scan

SUSPICIOUS_PATHS = ["/admin", "/wp-login", "/etc/passwd", "..", "shell",
                    "' or ", "union select", "id=1'"]
SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "nmap", "() {", "masscan"]

# ---- Per-IP sliding-window state --------------------------------------------
ssh_fails = defaultdict(deque)     # ip -> deque[timestamps]
fw_denies = defaultdict(deque)     # ip -> deque[(ts, port)]
web_hits = defaultdict(deque)      # ip -> deque[(ts, path)]

# Remember which alerts we already raised so we don't spam the console for the
# same ongoing attack every single event.
recent_alerts = {}                 # (rule, ip) -> last_alert_ts
ALERT_COOLDOWN = 20

alert_count = 0


def _trim(dq, window=WINDOW_SECONDS):
    """Drop entries older than the window from the left of a deque."""
    cutoff = time.time() - window
    while dq and (dq[0][0] if isinstance(dq[0], tuple) else dq[0]) < cutoff:
        dq.popleft()


def _should_alert(rule, ip):
    key = (rule, ip)
    last = recent_alerts.get(key, 0)
    if time.time() - last >= ALERT_COOLDOWN:
        recent_alerts[key] = time.time()
        return True
    return False


def raise_alert(severity, rule, ip, message, evidence):
    global alert_count
    alert_count += 1
    sev_color = {"CRITICAL": BG_RED + WHITE, "HIGH": RED, "MEDIUM": YELLOW}[severity]
    bar = "!" * 60
    print(f"\n{sev_color}{BOLD}{bar}{RESET}", flush=True)
    print(f"{sev_color}{BOLD}  ALERT #{alert_count}  [{severity}]  {rule}{RESET}", flush=True)
    print(f"{RED}{BOLD}  attacker : {ip}{RESET}", flush=True)
    print(f"{WHITE}  what     : {message}{RESET}", flush=True)
    print(f"{DIM}  evidence : {evidence}{RESET}", flush=True)
    print(f"{DIM}  time     : {time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}", flush=True)
    print(f"{sev_color}{BOLD}{bar}{RESET}\n", flush=True)


# ---- Detection rules --------------------------------------------------------
def rule_ssh(ev):
    if ev["category"] != "authentication" or not ev["src_ip"]:
        return
    ip = ev["src_ip"]
    if ev["outcome"] == "failure":
        ssh_fails[ip].append(time.time())
        _trim(ssh_fails[ip])
        n = len(ssh_fails[ip])
        if n >= SSH_FAIL_THRESHOLD and _should_alert("ssh_bruteforce", ip):
            raise_alert("HIGH", "SSH BRUTE FORCE", ip,
                        f"{n} failed SSH logins in {WINDOW_SECONDS}s",
                        f"target user='{ev['user']}'")
    elif ev["outcome"] == "success":
        # A success right after a pile of failures = likely compromised account.
        _trim(ssh_fails[ip])
        if len(ssh_fails[ip]) >= SSH_FAIL_THRESHOLD:
            raise_alert("CRITICAL", "BRUTE-FORCE LOGIN SUCCEEDED", ip,
                        f"successful SSH login after "
                        f"{len(ssh_fails[ip])} failures — account likely compromised",
                        f"user='{ev['user']}'")
            ssh_fails[ip].clear()


def rule_port_scan(ev):
    if ev["category"] != "network" or ev["outcome"] != "blocked" or not ev["src_ip"]:
        return
    ip = ev["src_ip"]
    fw_denies[ip].append((time.time(), ev["dst_port"]))
    _trim(fw_denies[ip])
    ports = {p for _, p in fw_denies[ip]}
    if len(ports) >= SCAN_PORT_THRESHOLD and _should_alert("port_scan", ip):
        raise_alert("MEDIUM", "PORT SCAN", ip,
                    f"firewall blocked {len(ports)} different ports in {WINDOW_SECONDS}s",
                    f"ports={sorted(list(ports))[:8]}...")


def rule_web_scan(ev):
    if ev["category"] != "web" or not ev["src_ip"]:
        return
    ip = ev["src_ip"]
    path = (ev["path"] or "").lower()
    agent = (ev["user_agent"] or "").lower()
    bad = (any(s in path for s in SUSPICIOUS_PATHS)
           or any(a in agent for a in SUSPICIOUS_AGENTS))
    if not bad:
        return
    web_hits[ip].append((time.time(), ev["path"]))
    _trim(web_hits[ip])
    n = len(web_hits[ip])
    if n >= WEB_HIT_THRESHOLD and _should_alert("web_scan", ip):
        raise_alert("HIGH", "WEB APPLICATION SCAN", ip,
                    f"{n} suspicious web requests in {WINDOW_SECONDS}s "
                    f"(attack tool or exploit paths)",
                    f"agent='{ev['user_agent']}' last_path='{ev['path']}'")


RULES = [rule_ssh, rule_port_scan, rule_web_scan]


def main():
    r = connect()
    banner(MAGENTA, "STAGE 3: CORRELATION & ALERTING (correlator)")
    print(f"{MAGENTA}Watching normalized events for attack patterns...{RESET}",
          flush=True)
    print(f"{DIM}Thresholds: SSH>={SSH_FAIL_THRESHOLD} fails, "
          f"scan>={SCAN_PORT_THRESHOLD} ports, web>={WEB_HIT_THRESHOLD} hits, "
          f"window={WINDOW_SECONDS}s{RESET}\n", flush=True)

    while True:
        ev = pop(r, Q_EVENTS)
        if ev is None:
            continue
        # Quiet heartbeat so students see events flowing even when no alert fires.
        print(f"{DIM}[correlate] examined {ev['event_id']} "
              f"({ev['category']}/{ev['action']}){RESET}", flush=True)
        for rule in RULES:
            rule(ev)


if __name__ == "__main__":
    main()
