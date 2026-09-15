#!/usr/bin/env python3
"""Drive the VyOS 'install image' installer over a raw-TCP serial console (used once to build images/vyos-base.qcow2).
Usage: vyos_install.py HOST PORT"""
import re, socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port)); s.settimeout(1)
buf = ""
def expect(pattern, timeout=180):
    global buf; t0 = time.time()
    while time.time() - t0 < timeout:
        try: buf += s.recv(65536).decode(errors="replace")
        except socket.timeout: pass
        m = re.search(pattern, buf[-4000:])
        if m: print(f"<< {m.group(0).strip()!r}"); buf = ""; return
    sys.exit(f"timeout waiting for {pattern!r}; last: {buf[-600:]!r}")
def send(text): print(f">> {text!r}"); s.sendall((text + "\r").encode()); time.sleep(0.5)
send(""); expect(r"login:"); send("vyos"); expect(r"[Pp]assword:"); send("vyos"); expect(r"vyos@vyos:~\$")
send("install image"); expect(r"continue\? \[y/N\]|Would you like to continue"); send("y")
expect(r"What would you like to name this image\?.*\]:", 300); send("")
expect(r"Please enter a password for the \"vyos\" user|password for the 'vyos' user|new password|Please enter a password", 60); send("vyos")
expect(r"console.*\[K\]:|Would you like to use a custom console|Please select console type|\[KSU\]", 30); send("S")
expect(r"Install the image on\?.*\]:|Please select drive|Install the image on", 60); send("")
expect(r"Installation will delete all data on the drive. Continue\? \[y/N\]|Continue\? \[y/N\]", 60); send("y")
expect(r"Would you like to use all the free space on the drive\? \[Y/n\]|use all the free space", 60); send("y")
expect(r"Are you sure you want to erase|Would you like to copy|Copying|completed|Copying files", 120)
expect(r"Would you like to copy config|copy.*config", 300); send("y")
expect(r"vyos@vyos:~\$", 600)
send("sudo poweroff"); time.sleep(3); print("installer done")
