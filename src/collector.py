"""
collector.py — STAGE 1 of 3: COLLECTION.

Job: ingest raw logs from every source and give each one a common "envelope"
before passing it down the pipeline. The collector does NOT try to understand
the contents of the log line yet — it only:

  1. receives the raw line,
  2. stamps it with a unique event id + the time we received it,
  3. records which source it came from,
  4. forwards it to the normalizer.

Think of this as the SIEM's front door: everything comes in here first.
"""
import itertools

from common import (connect, pop, push, Q_RAW, Q_COLLECTED, now_iso,
                    banner, GREEN, DIM, RESET, BOLD)

counter = itertools.count(1)


def main():
    r = connect()
    banner(GREEN, "STAGE 1: COLLECTION (collector)")
    print(f"{GREEN}Listening for raw logs from all sources...{RESET}\n", flush=True)

    while True:
        raw = pop(r, Q_RAW)
        if raw is None:
            continue

        event = {
            "event_id": f"evt-{next(counter):06d}",
            "received_at": now_iso(),
            "source": raw["source"],
            "raw": raw["line"],
        }
        push(r, Q_COLLECTED, event)

        print(f"{GREEN}[collect]{RESET} {BOLD}{event['event_id']}{RESET} "
              f"from {GREEN}{event['source']}{RESET} "
              f"{DIM}| {event['raw'][:70]}{RESET}", flush=True)


if __name__ == "__main__":
    main()
