#!/usr/bin/env python3
"""Regenerate docs/assets/demo.cast from REAL CloudKill output.

No mock data: every frame is the actual stdout of the installed CLI.
Usage:  python scripts/make-demo.py
"""

import json
import subprocess
import time
from pathlib import Path

COMMANDS = [
    ["cloudkill", "--version"],
    ["cloudkill", "--help"],
    ["cloudkill", "profiles"],
    ["cloudkill", "sources"],
]

CAST = Path(__file__).resolve().parent.parent / "docs" / "assets" / "demo.cast"
GREEN, RESET = "\x1b[38;5;114m", "\x1b[0m"


def main() -> None:
    events: list[list] = []
    clock = 0.8

    for cmd in COMMANDS:
        # echo the prompt like a real terminal
        events.append([round(clock, 2), "o", f"{GREEN}$ {RESET}" + " ".join(cmd) + "\r\n"])
        clock += 0.45

        out = subprocess.run(cmd, capture_output=True, text=True).stdout.rstrip()
        # stream line by line — reads like real terminal output
        for line in out.splitlines():
            events.append([round(clock, 2), "o", line + "\r\n"])
            clock += 0.05
        events.append([round(clock, 2), "o", "\r\n"])
        clock += 0.9

    header = {
        "version": 2,
        "width": 100,
        "height": 34,
        "timestamp": int(time.time()),
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    CAST.parent.mkdir(parents=True, exist_ok=True)
    with CAST.open("w") as f:
        f.write(json.dumps(header) + "\n")
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"demo.cast written: {CAST} ({len(events)} frames, {clock:.1f}s)")


if __name__ == "__main__":
    main()
