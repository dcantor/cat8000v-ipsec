#!/usr/bin/env python3
"""Turn a Robot Framework run into a one-file PDF of evidence: what was tested, what passed, how long it took, and — for the
tests that measure something (the NAT/DNS scale sweeps, capacity, the ping mesh) — the numbers they reported.

  tests/report_pdf.py [results/<run>]      (default: results/latest) -> <run>/report.pdf

Reads output.xml only, so it works for any past run. Rendered with headless Chrome through Playwright, like docs/build_pdf.py."""
import argparse
import html
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
p.add_argument("run", nargs="?", default=str(LAB / "results" / "latest"), help="results/<timestamp> directory")
p.add_argument("--out", help="output PDF (default: <run>/report.pdf)")
a = p.parse_args()
RUN = Path(a.run).resolve()
XML = RUN / "output.xml"
if not XML.exists(): sys.exit(f"no output.xml in {RUN}")
OUT = Path(a.out) if a.out else RUN / "report.pdf"

E = html.escape
root = ET.parse(XML).getroot()


def when(node, which):
    s = node.find("status")
    return (s.get(which) or "") if s is not None else ""


def seconds(node):
    s = node.find("status")
    if s is None: return 0.0
    if s.get("elapsed"): return float(s.get("elapsed"))
    fmt = "%Y%m%d %H:%M:%S.%f"
    try: return (datetime.strptime(s.get("endtime"), fmt) - datetime.strptime(s.get("starttime"), fmt)).total_seconds()
    except (TypeError, ValueError): return 0.0


def text_of(node, tag):
    x = node.find(tag)
    return " ".join((x.text or "").split()) if x is not None and x.text else ""


# ---- the numbers a test reported: lines from its keywords' messages that read like evidence -----------------------------------
EVIDENCE = re.compile(r"(?i)\b("
                      r"reached \d+|fixed up \d+/\d+|\d+/\d+ (?:checks ok|tests|compliance rows|IKEv2 SAs|tunnels)|"
                      r"Total active translations:[^\n]+|Success rate is \d+ percent[^\n]*|"
                      r"\d+ packets transmitted[^\n]*|Hits: \d+[^\n]*|resolved\+reached \d+/\d+|"
                      r"in sync|Established|(?-i:COMPLIANT))[^\n]*")     # COMPLIANT stays case-sensitive: a dict's 'compliant': True is not evidence


RANK = ((r"reached \d+|fixed up|resolved\+reached|checks ok|compliance rows|Total active translations|Hits:", 0),
        (r"IKEv2 SAs|tunnels|in sync|Established", 1))


def evidence(test, limit=3):
    """The lines a test printed that read like a measurement, best first and without near-duplicates — a ping that says the same
    thing six times is one piece of evidence, a translation count is another."""
    found = {}
    for msg in test.iter("msg"):
        t = " ".join(re.sub(r"<[^>]+>", " ", msg.text or "").split())
        if not t or len(t) > 500: continue
        for m in EVIDENCE.finditer(t):
            line = re.sub(r"[.\s]+$", "", " ".join(m.group(0).split())[:150])
            rank = next((r for pat, r in RANK if re.search(pat, line)), 2)
            key = re.sub(r"[\d./]+", "#", line.lower())[:30]     # same shape, different numbers (or cut short) -> keep the first only
            if key not in found: found[key] = (rank, len(found), line)
    return [line for _, _, line in sorted(found.values())[:limit]]


suites, totals = [], {"PASS": 0, "FAIL": 0, "SKIP": 0}
for suite in root.iter("suite"):
    tests = suite.findall("test")
    if not tests: continue
    rows = []
    for t in tests:
        st = when(t, "status")
        totals[st] = totals.get(st, 0) + 1
        rows.append({"name": t.get("name"), "status": st, "seconds": seconds(t), "doc": text_of(t, "doc"),
                     "message": " ".join((t.find("status").text or "").split())[:600] if t.find("status") is not None and t.find("status").text else "",
                     "evidence": evidence(t), "tags": [x.text for x in t.findall("tag")]})
    suites.append({"name": suite.get("name"), "doc": text_of(suite, "doc"), "tests": rows,
                   "seconds": sum(r["seconds"] for r in rows), "failed": sum(1 for r in rows if r["status"] == "FAIL")})

total = sum(len(s["tests"]) for s in suites)
started = root.get("generated") or ""
elapsed = sum(s["seconds"] for s in suites)
configs = sorted((RUN / "configs").glob("*/*.running-config.txt")) if (RUN / "configs").exists() else []
diff = (RUN / "configs" / "pre-vs-post.diff")
diff_lines = len(diff.read_text().splitlines()) if diff.exists() else 0

CSS = """
@page { size: A4; margin: 14mm 12mm }
body { font: 9.6pt/1.42 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1c2430; margin: 0 }
h1 { font-size: 21pt; margin: 0 0 2pt } h2 { font-size: 12.5pt; margin: 16pt 0 5pt; padding-bottom: 2pt; border-bottom: 2px solid #0b62d6; page-break-after: avoid }
.sub { color: #6b7684; font-size: 10pt } .meta { font-size: 9pt; color: #475569; margin-top: 6pt }
.kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8pt; margin: 10pt 0 4pt }
.kpi { border: 1px solid #d7dde5; border-radius: 6px; padding: 7pt 9pt } .kpi .v { font-size: 17pt; font-weight: 600 } .kpi .l { font-size: 8.4pt; color: #64748b }
.ok { color: #15803d } .bad { color: #b91c1c } .skip { color: #b26a00 }
table { border-collapse: collapse; width: 100%; table-layout: fixed; font-size: 8.8pt; margin: 4pt 0 8pt } tr { page-break-inside: avoid }
th, td { border: 1px solid #d7dde5; padding: 3.5pt 5pt; vertical-align: top; text-align: left } th { background: #eef2f7 }
td.s { white-space: nowrap; font-weight: 600 } td.t { white-space: nowrap; text-align: right; color: #475569 }
.doc { color: #475569; font-size: 8.2pt; margin-top: 2pt; overflow-wrap: anywhere }
.ev { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 7.6pt; color: #0f3f7a; margin-top: 2pt; overflow-wrap: anywhere }
.msg { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 7.9pt; color: #8a1c1c; margin-top: 2pt }
.suite-h { display: flex; justify-content: space-between; align-items: baseline } .small { font-size: 8.6pt; color: #64748b }
"""

rows_html = []
for s in suites:
    rows_html.append(f"""<h2>{E(s['name'])} <span class="small">— {len(s['tests'])} tests, {len(s['tests']) - s['failed']} passed, {s['failed']} failed · {s['seconds']:.0f}s</span></h2>""")
    if s["doc"]: rows_html.append(f'<div class="doc">{E(s["doc"])}</div>')
    rows_html.append('<table><tr><th style="width:46%">Test</th><th style="width:7%">Result</th><th style="width:6%">Time</th><th style="width:41%">Evidence</th></tr>')
    for t in s["tests"]:
        cls = {"PASS": "ok", "FAIL": "bad", "SKIP": "skip"}.get(t["status"], "")
        ev = "<br>".join(E(x) for x in t["evidence"])
        msg = f'<div class="msg">{E(t["message"])}</div>' if t["status"] == "FAIL" and t["message"] else ""
        rows_html.append(f"""<tr><td>{E(t['name'])}{f'<div class="doc">{E(t["doc"][:400])}</div>' if t['doc'] else ''}{msg}</td>
            <td class="s {cls}">{t['status']}</td><td class="t">{t['seconds']:.0f}s</td><td class="ev">{ev}</td></tr>""")
    rows_html.append("</table>")

doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Test evidence — {E(RUN.name)}</title><style>{CSS}</style></head><body>
<h1>C8000v IPsec lab — test evidence</h1>
<div class="sub">Robot Framework run <b>{E(RUN.name)}</b> · every test runs against the live lab: the routers, the firewalls, the LAN hosts, Nautobot and the portal</div>
<div class="kpis">
  <div class="kpi"><div class="v {'ok' if not totals.get('FAIL') else 'bad'}">{total - totals.get('FAIL', 0)} / {total}</div><div class="l">tests passed</div></div>
  <div class="kpi"><div class="v {'bad' if totals.get('FAIL') else 'ok'}">{totals.get('FAIL', 0)}</div><div class="l">failed</div></div>
  <div class="kpi"><div class="v skip">{totals.get('SKIP', 0)}</div><div class="l">skipped</div></div>
  <div class="kpi"><div class="v">{len(suites)}</div><div class="l">suites</div></div>
  <div class="kpi"><div class="v">{elapsed / 60:.0f} min</div><div class="l">wall clock</div></div>
</div>
<div class="meta">Generated {E(started)} · results in <code>{E(str(RUN))}</code> · {len(configs)} router configurations captured before and after the run{f', {diff_lines} lines of difference' if diff.exists() else ''} · log.html and report.html sit beside this file.</div>
{''.join(rows_html)}
</body></html>"""

tmp = RUN / ".evidence.html"          # never report.html: that is Robot's own report, and this file is deleted again below
tmp.write_text(doc)
from playwright.sync_api import sync_playwright   # noqa: E402
with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", headless=True); page = b.new_page()
    page.goto(tmp.as_uri(), wait_until="networkidle"); page.emulate_media(media="print")
    page.pdf(path=str(OUT), format="A4", print_background=True, margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"},
             display_header_footer=True, header_template="<div></div>",
             footer_template=f"<div style='font-size:8px;color:#888;width:100%;text-align:center'>C8000v IPsec lab — test evidence, run {E(RUN.name)} · page <span class='pageNumber'></span> / <span class='totalPages'></span></div>")
    b.close()
tmp.unlink(missing_ok=True)
print(f"{OUT} ({OUT.stat().st_size / 1024:.0f} KB) — {total - totals.get('FAIL', 0)}/{total} passed, {len(suites)} suites")
