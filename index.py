#!/usr/bin/env python3

import subprocess
import signal
import sys
import time
from pathlib import Path

modules_file = Path("modules.txt")
processes = []

def load_modules():
    if not modules_file.exists():
        return []
    with modules_file.open() as f:
        return [line.strip() for line in f if line.strip()]

def start_module(path):
    p = subprocess.Popen(["python3", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    processes.append((path, p))

def shutdown(sig, frame):
    for _, p in processes:
        p.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

for module in load_modules():
    start_module(module)

while True:
    time.sleep(5)
