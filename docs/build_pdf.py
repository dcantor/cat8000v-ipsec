#!/usr/bin/env python3
"""Render docs/workflows.html (Mermaid diagrams) to docs/workflows.pdf with headless Chrome."""
from pathlib import Path
from playwright.sync_api import sync_playwright
here = Path(__file__).resolve().parent
with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", headless=True); page = b.new_page(viewport={"width": 1100, "height": 1400})
    page.goto((here / "workflows.html").as_uri(), wait_until="networkidle")
    page.wait_for_function("document.querySelectorAll('pre.mermaid svg').length === document.querySelectorAll('pre.mermaid').length", timeout=120000); page.wait_for_timeout(1500)
    n = page.evaluate("document.querySelectorAll('pre.mermaid svg').length")
    errs = page.evaluate("[...document.querySelectorAll('pre.mermaid svg')].filter(s => (s.getAttribute('aria-roledescription') || '') === 'error' || s.querySelector('.error-text')).length")
    page.emulate_media(media="print")
    page.pdf(path=str(here / "workflows.pdf"), format="A4", print_background=True, margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
             display_header_footer=True, header_template="<div></div>",
             footer_template="<div style='font-size:8px;color:#888;width:100%;text-align:center'>VPN Provisioning Portal — workflows, data flows and decision trees · page <span class='pageNumber'></span> / <span class='totalPages'></span></div>")
    b.close()
print(f"rendered {n} diagrams ({errs} errors) -> {here / 'workflows.pdf'} ({(here / 'workflows.pdf').stat().st_size / 1e6:.1f} MB)")
