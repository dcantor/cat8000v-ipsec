# Documentation

- `workflows.pdf` — **Workflows, data flows and decision trees**: which system talks to which, over what
  protocol, with what data; sequence diagrams for deploy / dry run, add spoke, add headend, remove spoke,
  resume and inventory; decision trees for intent validation, spoke allocation, the Nautobot seed, the
  renderer, apply/convergence/Golden Config, bootstrap and VM wiring, removal; the REST API reference,
  the test coverage map and the file map.
- `workflows.html` is the source (Mermaid diagrams); rebuild the PDF with
  `webapp/.venv/bin/python docs/build_pdf.py` (headless Chrome via Playwright).
