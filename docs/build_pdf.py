#!/usr/bin/env python3
"""Render a docs/*.html document to PDF with headless Chrome (Mermaid diagrams, when present, are rendered first).
Usage: build_pdf.py [workflows.html | requirements.html ...]   (default: workflows.html; the PDF sits next to its source)"""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

here = Path(__file__).resolve().parent
docs = [here / n for n in (sys.argv[1:] or ["workflows.html"])]
with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", headless=True); page = b.new_page(viewport={"width": 1100, "height": 1400})
    for src in docs:
        page.goto(src.as_uri(), wait_until="networkidle")
        n = errs = 0
        if page.evaluate("document.querySelectorAll('pre.mermaid').length"):
            page.wait_for_function("document.querySelectorAll('pre.mermaid svg').length === document.querySelectorAll('pre.mermaid').length", timeout=120000); page.wait_for_timeout(1500)
            n = page.evaluate("document.querySelectorAll('pre.mermaid svg').length")
            errs = page.evaluate("[...document.querySelectorAll('pre.mermaid svg')].filter(s => (s.getAttribute('aria-roledescription') || '') === 'error' || s.querySelector('.error-text')).length")
        title = page.title()
        page.emulate_media(media="print")
        out = src.with_suffix(".pdf")
        page.pdf(path=str(out), format="A4", print_background=True, margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
                 display_header_footer=True, header_template="<div></div>",
                 footer_template=f"<div style='font-size:8px;color:#888;width:100%;text-align:center'>{title} · page <span class='pageNumber'></span> / <span class='totalPages'></span></div>")
        print(f"{src.name} -> {out.name} ({out.stat().st_size / 1e6:.1f} MB" + (f", {n} diagrams, {errs} errors" if n else "") + ")")
    b.close()
