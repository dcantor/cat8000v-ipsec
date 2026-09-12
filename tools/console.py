#!/usr/bin/env python3
"""Drive an IOS-XE serial console exposed as a raw TCP socket.

Usage:
  console.py wait  HOST PORT [TIMEOUT]         # wait until an exec prompt appears
  console.py send  HOST PORT CMD [CMD ...]     # run exec/config commands, print output
  console.py push  HOST PORT FILE              # push a config file (config lines), then write mem
"""
import re, socket, sys, time

PROMPT_RE = re.compile(rb'(?m)^[\w\-\.]+(\([\w\-\/]+\))?[>#] ?$')

class Console:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)))
        self.s.settimeout(1)
        self.buf = b""

    def read(self):
        try:
            d = self.s.recv(65536)
            if not d:
                raise ConnectionError("console closed")
            sys.stdout.write(d.decode(errors="replace")); sys.stdout.flush()
            self.buf += d
        except socket.timeout:
            pass

    def send(self, txt):
        self.s.sendall(txt.encode())

    def expect_prompt(self, timeout=30, nudge=False):
        """Return when a line ending in '>' or '#' (an exec/config prompt) is seen."""
        end = time.time() + timeout
        last_nudge = 0
        while time.time() < end:
            self.read()
            tail = self.buf[-4096:]
            # Handle the interactive first-boot dialogs.
            if re.search(rb'\[yes/no\]:\s*$', tail):      # setup dialog, "replace keys?" etc.
                self.send("no\r"); self.buf = b""; continue
            if re.search(rb'terminate autoinstall\? \[yes\]:\s*$', tail):
                self.send("yes\r"); self.buf = b""; continue
            if re.search(rb'[Pp]assword:\s*$', tail):
                self.send("admin\r"); self.buf = b""; continue
            if re.search(rb'Username:\s*$', tail):
                self.send("admin\r"); self.buf = b""; continue
            if PROMPT_RE.search(tail.rstrip(b' ')):
                return tail
            if nudge and time.time() - last_nudge > 15:
                self.send("\r"); last_nudge = time.time()
        raise TimeoutError("no prompt within %ss" % timeout)

    def cmd(self, line, timeout=60):
        self.buf = b""
        self.send(line + "\r")
        time.sleep(0.2)
        return self.expect_prompt(timeout)

    def ensure_enable(self):
        tail = self.expect_prompt(30, nudge=True)
        if tail.rstrip().endswith(b'>'):
            self.cmd("enable")
        self.cmd("terminal length 0")
        self.cmd("terminal width 511")

def main():
    op, host, port = sys.argv[1:4]
    c = Console(host, port)
    if op == "wait":
        t = int(sys.argv[4]) if len(sys.argv) > 4 else 900
        c.expect_prompt(t, nudge=True)
        print("\n[console] prompt ready")
    elif op == "send":
        c.ensure_enable()
        for line in sys.argv[4:]:
            c.cmd(line, timeout=180)
        print()
    elif op == "push":
        c.ensure_enable()
        c.cmd("configure terminal")
        for line in open(sys.argv[4]):
            line = line.rstrip()
            if not line or line.startswith("!") or line in ("end",):
                continue
            c.cmd(line, timeout=180)   # crypto key generate can take a while
        c.cmd("end")
        c.cmd("write memory", timeout=120)
        print("\n[console] config pushed and saved")
    else:
        sys.exit(__doc__)

if __name__ == "__main__":
    main()
