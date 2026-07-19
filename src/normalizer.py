"""
normalizer.py — STAGE 2 of 3: NORMALIZATION.

Job: turn many different raw log formats into ONE common event schema so the
correlator can reason about them uniformly. This is the heart of why a SIEM is
useful — an SSH log, a firewall log, and a web log look nothing alike, but
after normalization they all share the same fields:

    { event_id, source, timestamp, category, action, outcome,
      src_ip, user, dst_port, path, user_agent, http_status, raw }

We use one regular expression per source format to pull the interesting
fields out of the raw text. Anything we cannot parse is marked "unparsed" and
still forwarded (a real SIEM never silently drops data).
"""
import re

from common import (connect, pop, push, Q_COLLECTED, Q_EVENTS, now_iso,
                    banner, YELLOW, DIM, RESET, BOLD, RED, GREEN)

# ---- One regex per source format --------------------------------------------
RE_AUTH = re.compile(
    r"sshd\[\d+\]:\s+(?P<result>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)")

RE_FW = re.compile(
    r"FW:\s+(?P<action>DENY|ALLOW)\s+\w+\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+"
    r"\d+\.\d+\.\d+\.\d+:(?P<dst_port>\d+)")

RE_WEB = re.compile(
    r'^(?P<src_ip>\d+\.\d+\.\d+\.\d+).*"'
    r'(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3}).*"(?P<agent>[^"]*)"$')


def base_event(collected):
    """Every normalized event starts with these shared fields."""
    return {
        "event_id": collected["event_id"],
        "source": collected["source"],
        "timestamp": now_iso(),
        "category": "unknown",
        "action": None,
        "outcome": None,
        "src_ip": None,
        "user": None,
        "dst_port": None,
        "path": None,
        "user_agent": None,
        "http_status": None,
        "raw": collected["raw"],
    }


def normalize(collected):
    ev = base_event(collected)
    line = collected["raw"]
    src = collected["source"]

    if src == "auth":
        m = RE_AUTH.search(line)
        if m:
            ev.update(category="authentication",
                      action="ssh_login",
                      outcome="success" if m["result"] == "Accepted" else "failure",
                      user=m["user"], src_ip=m["src_ip"])
    elif src == "firewall":
        m = RE_FW.search(line)
        if m:
            ev.update(category="network",
                      action="firewall_" + m["action"].lower(),
                      outcome="blocked" if m["action"] == "DENY" else "allowed",
                      src_ip=m["src_ip"], dst_port=int(m["dst_port"]))
    elif src == "web":
        m = RE_WEB.search(line)
        if m:
            ev.update(category="web",
                      action="http_" + m["method"].lower(),
                      outcome="error" if m["status"][0] in "45" else "ok",
                      src_ip=m["src_ip"], path=m["path"],
                      user_agent=m["agent"], http_status=int(m["status"]))

    if ev["category"] == "unknown":
        ev["category"] = "unparsed"
    return ev


def pretty(ev):
    """One tidy human-readable line summarizing the normalized event."""
    oc = ev["outcome"]
    color = RED if oc in ("failure", "blocked", "error") else GREEN
    bits = [f"{BOLD}{ev['event_id']}{RESET}",
            f"{YELLOW}{ev['category']}{RESET}",
            f"{ev['action']}"]
    if ev["src_ip"]:
        bits.append(f"src={ev['src_ip']}")
    if ev["user"]:
        bits.append(f"user={ev['user']}")
    if ev["dst_port"]:
        bits.append(f"dport={ev['dst_port']}")
    if ev["path"]:
        bits.append(f"path={ev['path']}")
    if oc:
        bits.append(f"{color}{oc}{RESET}")
    return "  ".join(bits)


def main():
    r = connect()
    banner(YELLOW, "STAGE 2: NORMALIZATION (normalizer)")
    print(f"{YELLOW}Parsing raw logs into a common event schema...{RESET}\n",
          flush=True)

    while True:
        collected = pop(r, Q_COLLECTED)
        if collected is None:
            continue
        ev = normalize(collected)
        push(r, Q_EVENTS, ev)
        print(f"{YELLOW}[normalize]{RESET} {pretty(ev)}", flush=True)


if __name__ == "__main__":
    main()
