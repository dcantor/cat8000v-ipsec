#!/usr/bin/env python3
"""VyOS serial-console helper (raw TCP): wait for the login prompt, or push a file of 'set ...' lines (login,
configure, set*, commit, save, exit).   vyos_console.py wait HOST PORT [TIMEOUT] | push HOST PORT FILE | send HOST PORT CMD"""
import re, socket, sys, time
cmd, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.create_connection((host, port)); s.settimeout(1); buf = ""
def rd(t=2):
    global buf; t0 = time.time()
    while time.time() - t0 < t:
        try: buf += s.recv(65536).decode(errors="replace")
        except socket.timeout: pass
def until(pat, t=120, nudge=None):
    global buf; t0 = time.time(); last = 0
    while time.time() - t0 < t:
        rd(2)
        if re.search(pat, buf[-3000:]): return True
        if nudge and time.time() - last > 10: s.sendall(nudge); last = time.time()
    return False
def login():
    global buf
    s.sendall(b"\r"); rd(2)
    if re.search(r"[$#] *$", buf[-200:]): buf = ""; return
    if not until(r"login: *$", 30, b"\r"): sys.exit("no login prompt")
    buf = ""; s.sendall(b"vyos\r"); until(r"assword:", 20); buf = ""; s.sendall(b"vyos\r")
    if not until(r"\$ *$", 60): sys.exit("login failed"); 
    buf = ""
if cmd == "wait":
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 600
    if not until(r"login: *$|\$ *$", timeout, b"\r"): sys.exit("timeout waiting for VyOS prompt")
    print("prompt")
elif cmd == "push":
    login(); lines = [l.strip() for l in open(sys.argv[4]) if l.strip() and not l.startswith("#")]
    s.sendall(b"configure\r"); until(r"# *$", 30); buf = ""
    for l in lines:
        s.sendall((l + "\r").encode()); until(r"# *$", 60)
        if re.search(r"Invalid|Error|invalid", buf): print("!!", l, buf[-300:]); 
        buf = ""
    s.sendall(b"commit\r"); until(r"# *$", 180); print(buf[-400:]); buf = ""
    s.sendall(b"save\r"); until(r"# *$", 60); buf = ""; s.sendall(b"exit\r"); until(r"\$ *$", 30); print("pushed")
elif cmd == "send":
    login(); s.sendall((sys.argv[4] + "\r").encode()); until(r"\$ *$", 120); print(buf)
