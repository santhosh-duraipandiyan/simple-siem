# Simple SIEM 

A tiny, console-based **SIEM** (Security Information and Event Management)
system you can run on your laptop to *see* how the three core stages of a SIEM
work together:

```
 SIMULATED DEVICES      STAGE 1          STAGE 2            STAGE 3
 ┌───────────┐        ┌──────────┐     ┌────────────┐     ┌──────────────┐
 │ generator │ ─────▶ │ collector│ ──▶ │ normalizer │ ──▶ │  correlator  │
 │ (fake     │  raw   │(collect) │     │ (parse into│     │ (detect &    │
 │  logs)    │  logs  │          │     │  1 schema) │     │  ALERT)      │
 └───────────┘        └──────────┘     └────────────┘     └──────────────┘
        every arrow is a Redis queue (the "conveyor belt")
```

Everything runs in Docker. **One command starts the whole thing.**

📖 **Want the full explanation?** See [DOCUMENTATION.md](DOCUMENTATION.md) for
what a SIEM is and how each part of this system maps to a real one, the
[architecture diagram](docs/architecture.png), or the printable
[Understanding-SIEM.pdf](docs/Understanding-SIEM.pdf).

---

## Quick start

You need Docker Desktop (or Docker Engine + Compose) installed.

```bash
cd simple-siem
docker compose up --build
```

That's it. You'll see color-coded logs from all five containers interleaved in
your terminal. Within a minute or two the generator launches a scripted attack
and the **correlator prints a red ALERT box**.

Stop everything with `Ctrl+C`, then clean up with:

```bash
docker compose down
```

### Tip: watch one stage at a time

The combined stream is busy on purpose (it shows the whole pipeline). To focus
on just the alerts, open a second terminal and run:

```bash
docker compose logs -f correlator
```

Swap `correlator` for `collector`, `normalizer`, or `generator` to watch any
single stage.

---

## The three stages (what to study)

### Stage 1 — Collection (`src/collector.py`)
Takes in raw log lines from every source and wraps each one in a common
"envelope" (unique id, received time, source name). It does **not** interpret
the contents yet. This is the SIEM's front door.

### Stage 2 — Normalization (`src/normalizer.py`)
The most important idea in a SIEM. Raw logs come in totally different formats:

```
auth      Jul 18 10:22:01 web01 sshd[4521]: Failed password for root from 203.0.113.45 port 52344 ssh2
firewall  Jul 18 10:22:02 FW: DENY TCP 198.51.100.23:44123 -> 10.0.0.5:3389 len=52
web       192.0.2.10 - - [18/Jul/2026:10:22:05 +0000] "GET /admin.php HTTP/1.1" 404 512 "-" "sqlmap/1.5"
```

The normalizer uses one regular expression per format to turn all of them into
the **same schema**:

```json
{ "event_id": "...", "category": "authentication", "action": "ssh_login",
  "outcome": "failure", "src_ip": "203.0.113.45", "user": "root", ... }
```

Now different log types can be compared and counted together.

### Stage 3 — Correlation & Alerting (`src/correlator.py`)
Looks *across many events over time* to spot attacks. One failed login is
nothing; many from one IP is a brute-force attack. Built-in rules:

| Rule | Fires when | Severity |
|------|-----------|----------|
| SSH brute force | ≥ 5 failed SSH logins from one IP in 30s | HIGH |
| Brute-force success | a successful login right after those failures | CRITICAL |
| Port scan | one IP blocked on ≥ 10 different ports in 30s | MEDIUM |
| Web app scan | ≥ 4 suspicious web requests (sqlmap, `/admin`, `../`, SQLi) | HIGH |

All thresholds are constants at the top of `correlator.py` — change them and
re-run to experiment.

---

## How the pieces connect

`src/common.py` holds the shared plumbing: connecting to Redis, pushing/popping
JSON messages, colors, and banners. Each stage is a short loop:

```
while True:
    msg = pop(from_my_input_queue)   # blocks until work arrives
    result = do_my_job(msg)
    push(to_the_next_queue, result)
```

The queues (Redis lists):

```
generator  --[ raw_logs  ]-->  collector
collector  --[ collected ]-->  normalizer
normalizer --[ events    ]-->  correlator
```

Because the stages only talk through queues, each is an independent container.
This is exactly how real SIEM pipelines decouple ingestion, parsing, and
detection so each part can scale or be replaced on its own.

---

## Project layout

```
simple-siem/
├── docker-compose.yml   # starts all 5 containers with one command
├── Dockerfile           # one image, shared by all Python services
├── requirements.txt     # just the redis client
├── README.md
└── src/
    ├── common.py        # shared helpers (Redis, colors, queues)
    ├── generator.py     # simulated log sources + scripted attacks
    ├── collector.py     # STAGE 1: collection
    ├── normalizer.py    # STAGE 2: normalization
    └── correlator.py    # STAGE 3: correlation & alerting
```

