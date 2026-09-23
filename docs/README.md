# Documentation

- `workflows.pdf` — **Workflows, data flows and decision trees**: which system talks to which, over what
  protocol, with what data; sequence diagrams for deploy / dry run, add spoke, add headend, remove spoke,
  resume and inventory; decision trees for intent validation, spoke allocation, the Nautobot seed, the
  renderer, apply/convergence/Golden Config, bootstrap and VM wiring, removal; the REST API reference,
  the test coverage map and the file map.
- `workflows.html` is the source (Mermaid diagrams); rebuild the PDF with
  `webapp/.venv/bin/python docs/build_pdf.py` (headless Chrome via Playwright).
- `captures/dns-acme-side.pcap`, `captures/dns-acquisition-side.pcap` — the same DNS answer captured on both of the DCI's
  interfaces, written by `tools/dns_capture.py` (Embedded Packet Capture on the router, decoded and saved locally). Open them
  in Wireshark side by side: same transaction id, same question, `10.129.244.2` inside and `100.97.244.2` outside.
- `dci.pdf` — **The DCI: an acquired company inside the VPN**: the interconnect's topology, the path a branch takes to
  the acquisition (with real traceroutes), the routes exchanged and the route filter that keeps each side's copy of an
  overlapping prefix at home, the twice-NAT address model and its configuration, the DNS fix-up in both directions, and
  how suite 12 sweeps 1000 prefixes and 1000 records and what a run leaves behind. `dci.html` is the source;
  rebuild with `webapp/.venv/bin/python docs/build_pdf.py dci.html`. Every command output in it is from the live lab, and the
  appendix carries the configuration of `host-spoke1`, the `DCI` and the acquisition's DNS server (from the last run's
  `configs/post-run/`, with the thousand generated lines collapsed) and a full topology diagram of the lab — every VM,
  every link, the ten VTIs and the DCI chain — with the tunnel and router tables, all generated from `lab.conf` and the intent.
- `requirements.pdf` / `requirements.xlsx` — the **requirements specification** of the service: 106 numbered requirements
  (NET, SOT, INT, NAC, FW, PKI, CUST, HOST, INET, SEC, RUN, UI, CMP, API, MON, TST, LAB, DOC, NFR) with a MUST / SHOULD / MAY
  priority, acceptance criteria and the Robot suite or code that verifies each, plus the system context, roles and glossary,
  constraints and a traceability matrix. `requirements.html` is the single source:
  `webapp/.venv/bin/python docs/build_pdf.py requirements.html` renders the PDF and
  `webapp/.venv/bin/python docs/build_xlsx.py` writes the workbook (Overview with the count per area, Requirements —
  filterable and frozen, Roles & glossary, Traceability, Constraints). Edit the HTML, rebuild both.
- `screenshots/` — the README's screenshots of the portal and of Nautobot; re-capture them with
  `webapp/.venv/bin/python docs/screenshots.py` (headless Chrome via Playwright, signs into the portal as the lab's default
  approver and into Nautobot as admin; the lab must be up — it runs the ping mesh and reads the routers).
