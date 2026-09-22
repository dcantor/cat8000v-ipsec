# Documentation

- `workflows.pdf` — **Workflows, data flows and decision trees**: which system talks to which, over what
  protocol, with what data; sequence diagrams for deploy / dry run, add spoke, add headend, remove spoke,
  resume and inventory; decision trees for intent validation, spoke allocation, the Nautobot seed, the
  renderer, apply/convergence/Golden Config, bootstrap and VM wiring, removal; the REST API reference,
  the test coverage map and the file map.
- `workflows.html` is the source (Mermaid diagrams); rebuild the PDF with
  `webapp/.venv/bin/python docs/build_pdf.py` (headless Chrome via Playwright).
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
