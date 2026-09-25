#!/usr/bin/env python3
"""Build docs/portal-workflows.pptx — the executive overview of the portal's workflows, screenshot by screenshot.

One layout description drives two outputs: the PowerPoint itself, and an HTML replica at the same coordinates that a
browser can render, because this host has no LibreOffice and a deck nobody has looked at is a deck nobody should send.
   build_deck.py            build the .pptx and the preview
   build_deck.py --preview  the preview only
Screenshots come from docs/screenshots (captured against the live lab by docs/screenshots.py)."""
import html as htmlmod
import json
import subprocess
import sys
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
SHOTS = HERE / "screenshots"
OUT = HERE / "portal-workflows.pptx"
W, H = 13.333, 7.5                      # LAYOUT_WIDE

# The product's own colours: the portal's header ink and its orange accent, a light ground, one green for "it passed".
INK, NAVY, ACCENT = "0B1020", "1B2A4A", "C2410C"
GROUND, CARD, LINE = "F7F8FA", "FFFFFF", "DDE3EC"
BODY, MUTED, GREEN = "1F2937", "667085", "15803D"
HEAD_FONT, BODY_FONT = "Cambria", "Calibri"

slides = []          # each: {"bg": hex, "items": [...]}


def slide(bg=GROUND):
    slides.append({"bg": bg, "items": []}); return slides[-1]


def text(s, x, y, w, h, size=16, color=BODY, bold=False, font=BODY_FONT, align="l", anchor="t", spacing=1.15, italic=False):
    s["items"].append({"k": "text", "t": "", "x": x, "y": y, "w": w, "h": h, "size": size, "color": color,
                       "bold": bold, "font": font, "align": align, "anchor": anchor, "spacing": spacing, "italic": italic})
    return s["items"][-1]


def para(item, txt, size=None, color=None, bold=False, italic=False, space_after=6, bullet=False):
    item.setdefault("paras", []).append({"txt": txt, "size": size or item["size"], "color": color or item["color"],
                                         "bold": bold, "italic": italic, "space_after": space_after, "bullet": bullet})


def box(s, x, y, w, h, fill=CARD, line=LINE, radius=0.06, width=1):
    s["items"].append({"k": "box", "x": x, "y": y, "w": w, "h": h, "fill": fill, "line": line, "radius": radius, "lw": width})


def circle(s, x, y, d, fill=ACCENT, label=None, color="FFFFFF", size=15):
    s["items"].append({"k": "circle", "x": x, "y": y, "w": d, "h": d, "fill": fill, "label": label, "color": color, "size": size})


def shot(s, name, x, y, w=None, h=None, frame=True):
    """Place a screenshot, scaled to fit the given width or height without distorting it."""
    iw, ih = Image.open(SHOTS / f"{name}.png").size
    ratio = iw / ih
    if w and not h: h = w / ratio
    elif h and not w: w = h * ratio
    elif w and h:                                  # fit inside the box
        if w / h > ratio: w = h * ratio
        else: h = w / ratio
    if frame: box(s, x - 0.06, y - 0.06, w + 0.12, h + 0.12, fill=CARD, line=LINE, radius=0.04)
    s["items"].append({"k": "img", "src": str(SHOTS / f"{name}.png"), "x": x, "y": y, "w": w, "h": h})
    return w, h


def caption(s, txt, x, y, w, size=11):
    it = text(s, x, y, w, 0.35, size=size, color=MUTED)
    para(it, txt, space_after=0)


def title_slide():
    s = slide(INK)
    t = text(s, 0.9, 2.15, 9.6, 1.9, size=40, color="FFFFFF", bold=True, font=HEAD_FONT, spacing=1.0)
    para(t, "The VPN Provisioning Portal", space_after=2)
    sub = text(s, 0.9, 3.75, 9.8, 1.0, size=18, color="C7D2E4")
    para(sub, "An executive overview of the workflows — every screen an operator touches, in order", space_after=0)
    m = text(s, 0.9, 5.15, 11.5, 0.9, size=13, color="8FA3BF")
    para(m, "Managed IPsec VPN service · Catalyst 8000v VTI + eBGP · Nautobot source of truth · Network-as-Code (Terraform) · Robot Framework validation", space_after=0)
    circle(s, 11.15, 2.25, 1.25, fill=ACCENT)
    n = text(s, 11.15, 2.62, 1.25, 0.6, size=30, color="FFFFFF", bold=True, align="c", font=HEAD_FONT)
    para(n, "12", space_after=0)
    l = text(s, 10.38, 3.62, 2.2, 0.5, size=12, color="C7D2E4", align="c")
    para(l, "workflows, one screen", space_after=0)


def stat_slide():
    s = slide()
    h = text(s, 0.75, 0.55, 11.8, 0.8, size=32, color=INK, bold=True, font=HEAD_FONT)
    para(h, "What the portal runs", space_after=0)
    sub = text(s, 0.75, 1.32, 11.8, 0.5, size=14, color=MUTED)
    para(sub, "The live service, as the portal itself reports it — every number below is read from the routers and from Nautobot, never typed in.", space_after=0)
    stats = [("20", "routers onboarded", "3 headends · 4 branches · firewalls, hosts and the interconnect"),
             ("10 / 10", "tunnels up", "one static IPsec VTI per branch per headend, each with eBGP"),
             ("74", "tests per change", "the Robot Framework suites run at the end of a job"),
             ("~15 min", "to add a branch", "VM, onboarding, model, Terraform apply and tests")]
    x = 0.75
    for big, small, note in stats:
        box(s, x, 2.05, 2.85, 2.05)
        b = text(s, x + 0.25, 2.25, 2.4, 0.75, size=30, color=ACCENT, bold=True, font=HEAD_FONT)
        para(b, big, space_after=0)
        l = text(s, x + 0.25, 2.95, 2.4, 0.4, size=13, color=INK, bold=True)
        para(l, small, space_after=0)
        n = text(s, x + 0.25, 3.32, 2.4, 0.75, size=10.5, color=MUTED, spacing=1.15)
        para(n, note, space_after=0)
        x += 3.05
    box(s, 0.75, 4.45, 11.83, 2.25, fill="FFFFFF")
    q = text(s, 1.1, 4.75, 11.1, 1.9, size=15, color=BODY, spacing=1.35)
    para(q, "The portal is the only place the service is changed.", bold=True, space_after=8)
    para(q, "An operator states intent on a form; the portal writes it to the intent document, seeds Nautobot, renders the "
            "Network-as-Code data from Nautobot, plans and applies Terraform against the routers, then runs the test suites "
            "and keeps the evidence. Nobody logs into a router to make a change.", space_after=0)


def launcher_slide():
    s = slide()
    h = text(s, 0.75, 0.5, 11.8, 0.8, size=30, color=INK, bold=True, font=HEAD_FONT)
    para(h, "One screen: \u201cwhat do you want to do?\u201d", space_after=0)
    sb = text(s, 0.75, 1.28, 11.8, 0.45, size=13.5, color=MUTED)
    para(sb, "The Provision tab opens on the task, not on a form. Each card says what the job does, how long it takes and who may start it.", space_after=0)
    w, hh = shot(s, "portal-provision", 5.15, 1.95, w=7.4, h=4.5)
    caption(s, "Provision \u2014 the task launcher; every card is one job", 5.15, 1.95 + hh + 0.16, w)
    box(s, 0.75, 1.95, 4.0, hh)
    b = text(s, 1.03, 2.2, 3.44, hh - 0.5, size=12.5, color=BODY, spacing=1.3)
    para(b, "BUILD", size=11, color=MUTED, bold=True, space_after=3)
    para(b, "Add a branch \u00b7 Add a headend", space_after=11)
    para(b, "CHANGE A BRANCH", size=11, color=MUTED, bold=True, space_after=3)
    para(b, "Change IKE authentication \u00b7 Rotate a pre-shared key \u00b7 Renew a certificate \u00b7 Re-home \u00b7 Remove", space_after=11)
    para(b, "THE WHOLE SERVICE", size=11, color=MUTED, bold=True, space_after=3)
    para(b, "Deploy the model \u00b7 Dry run \u00b7 Run the tests \u00b7 Edit the service model", space_after=11)
    para(b, "CONFIGURATION", size=11, color=MUTED, bold=True, space_after=3)
    para(b, "Check for drift \u00b7 See what is running", space_after=14)
    para(b, "Each card carries its own duration and the role it needs \u2014 five minutes to rotate a key, about fifteen to "
            "build a branch, and an approver before anything is removed.", size=11.5, color=MUTED, space_after=0)


def anatomy_slide():
    s = slide()
    h = text(s, 0.75, 0.5, 11.8, 0.8, size=30, color=INK, bold=True, font=HEAD_FONT)
    para(h, "Every job looks the same", space_after=0)
    sub = text(s, 0.75, 1.28, 11.8, 0.45, size=13.5, color=MUTED)
    para(sub, "Pick a task, review what it will do, then watch it run on its own page — steps, live log, tests, ticket.", space_after=0)
    w, hh = shot(s, "portal-job", 0.75, 1.95, w=7.5, h=4.55)
    caption(s, "A finished job: nine steps, 74/74 tests, who started it and against which change ticket", 0.75, 1.95 + hh + 0.16, w)
    x = 0.75 + w + 0.4
    box(s, x, 1.95, W - x - 0.75, hh)
    it = text(s, x + 0.3, 2.2, W - x - 1.35, hh - 0.5, size=12.5, color=BODY, spacing=1.3)
    para(it, "What that gives you", bold=True, size=14, color=INK, space_after=10)
    para(it, "One job at a time — two changes can never race each other on the same router.", space_after=9)
    para(it, "Every step names what it did: how many objects Nautobot changed, what Terraform added and destroyed.", space_after=9)
    para(it, "A failed job resumes from the failed step; the successful steps are not repeated.", space_after=9)
    para(it, "The tests are part of the job, not an afterthought — the evidence is attached to it.", space_after=0)


def step_slide(n, title, sub, img, note, img_w=8.4, img_h=4.75, right_text=True):
    """`n` numbers a step *within a workflow* — the walkthrough of adding a branch. Slides that stand on their own
    carry no badge, so the numbers never read as one long sequence."""
    s = slide()
    tx = 0.75
    if n:
        circle(s, 0.75, 0.5, 0.62, fill=ACCENT)
        num = text(s, 0.75, 0.62, 0.62, 0.45, size=17, color="FFFFFF", bold=True, align="c", font=HEAD_FONT)
        para(num, str(n), space_after=0)
        tx = 1.55
    h = text(s, tx, 0.48, W - tx - 0.75, 0.65, size=28, color=INK, bold=True, font=HEAD_FONT)
    para(h, title, space_after=0)
    sb = text(s, tx, 1.15, W - tx - 0.75, 0.45, size=13.5, color=MUTED)
    para(sb, sub, space_after=0)
    w, hh = shot(s, img, 0.75, 1.85, w=img_w, h=img_h)
    caption(s, note, 0.75, 1.85 + hh + 0.16, w)
    return s, 0.75 + w + 0.45, hh


def side_note(s, x, items, y=1.85, w=None, title=None, h=4.5):
    w = w or (W - x - 0.75)
    box(s, x, y, w, h)
    it = text(s, x + 0.28, y + 0.25, w - 0.56, h - 0.5, size=12.5, color=BODY, spacing=1.3)
    if title: para(it, title, bold=True, size=14, color=INK, space_after=10)
    for i, t in enumerate(items):
        para(it, t, space_after=0 if i == len(items) - 1 else 9)


def two_up_slide(title, sub, left, right, lcap, rcap, notes):
    s = slide()
    h = text(s, 0.75, 0.5, 11.8, 0.8, size=30, color=INK, bold=True, font=HEAD_FONT)
    para(h, title, space_after=0)
    sb = text(s, 0.75, 1.28, 11.8, 0.45, size=13.5, color=MUTED)
    para(sb, sub, space_after=0)
    from PIL import Image as _I
    def fit(name, w, h):
        iw, ih = _I.open(SHOTS / f"{name}.png").size
        r = iw / ih
        return (h * r, h) if w / h > r else (w, w / r)
    lw, lh = fit(left, 5.85, 3.5); rw, rh = fit(right, 5.6, 3.5)
    band = max(lh, rh)
    shot(s, left, 0.75, 1.95 + (band - lh) / 2, w=lw, h=lh)
    caption(s, lcap, 0.75, 1.95 + band + 0.14, lw)
    shot(s, right, 6.95, 1.95 + (band - rh) / 2, w=rw, h=rh)
    caption(s, rcap, 6.95, 1.95 + band + 0.14, rw)
    y = 1.95 + band + 0.62
    it = text(s, 0.75, y, 11.8, 7.2 - y, size=12.5, color=BODY, spacing=1.3)
    for i, t in enumerate(notes):
        para(it, t, space_after=0 if i == len(notes) - 1 else 7)
    return s


def close_slide():
    s = slide(INK)
    h = text(s, 0.9, 0.9, 11.5, 0.9, size=32, color="FFFFFF", bold=True, font=HEAD_FONT)
    para(h, "What the UI is for", space_after=0)
    cols = [("Anyone can run it", "The knowledge is in the forms, not in an engineer's head: every value is suggested from "
                                  "the model and validated against the live lab before anything is applied."),
            ("Nothing happens off the record", "Sign-in, role, change ticket, the steps, the log and the test report are kept "
                                               "with the job. The audit page lists every action the portal took."),
            ("The model stays true", "Golden Config compares the routers against what Nautobot says they should be; drift is "
                                     "visible on one page and remediated as a job of its own.")]
    x = 0.9
    for t, b in cols:
        box(s, x, 2.15, 3.72, 2.75, fill=NAVY, line=NAVY)
        ht = text(s, x + 0.3, 2.42, 3.12, 0.6, size=16, color="FFFFFF", bold=True, font=HEAD_FONT)
        para(ht, t, space_after=0)
        bt = text(s, x + 0.3, 3.05, 3.12, 1.7, size=12, color="C7D2E4", spacing=1.3)
        para(bt, b, space_after=0)
        x += 3.92
    f = text(s, 0.9, 5.5, 11.5, 1.1, size=13, color="8FA3BF", spacing=1.3)
    para(f, "The portal is at http://192.168.50.231:8090 — Provision to start a job, Jobs to see every one that has run, "
            "Home for the service as it stands. The full specification (115 requirements) is docs/requirements.pdf.", space_after=0)


# ---------------------------------------------------------------- the deck
title_slide()
stat_slide()
launcher_slide()
anatomy_slide()

s, x, ih = step_slide(1, "Add a branch — who it is", "The wizard opens with the identity of the new site; the fields it can work out, it fills in.",
                  "portal-wizard-1", "Step 1 of 3 — name, site, customer, and the headends this branch will reach", img_w=8.1)
side_note(s, x, h=ih, items=["The branch name and its customer come from the service model; the portal checks the name is free in Nautobot and in the lab.",
                 "Choosing two headends is what makes the branch dual-homed — the wizard will allocate a tunnel to each.",
                 "Nothing is created yet. Cancel costs nothing."], title="What happens here")

s, x, ih = step_slide(2, "Add a branch — where it lives", "Addressing is allocated for you: router-id, LAN, AS number, ports, WAN /30s and tunnel numbers.",
                  "portal-wizard-2", "Step 2 of 3 — every field suggested from the next free value, and editable", img_w=8.1)
side_note(s, x, h=ih, items=["Each headend line shows the free ports on its firewall and how many tunnel slots remain — capacity is part of the form.",
                 "The convention is stated where it is applied: the hub takes the first address of each /30, the spoke the second.",
                 "Change any value and the portal re-validates it against the live lab, not against a stale copy."], title="Allocation, not arithmetic")

s, x, ih = step_slide(3, "Add a branch — confirm, then provision", "The last step is the whole change in one place: what will be created, on which devices, under which ticket.",
                  "portal-wizard-3", "Step 3 of 3 — review and provision", img_w=8.1)
side_note(s, x, h=ih, items=["The change ticket is required: it travels with the job and appears in the audit trail.",
                 "Provisioning is one job — VM, onboarding, Nautobot, Terraform on both ends, then the tests.",
                 "About fifteen minutes later the branch is carrying traffic and the tests say so."], title="One button, one job")

s, x, ih = step_slide(4, "Add a branch — watch it run", "The job page streams each step as it completes, with what that step actually changed.",
                  "portal-run", "The pipeline: validate intent → save intent → seed Nautobot → render NaC → Terraform plan → apply → tests", img_w=11.8, img_h=4.3)
caption(s, "Recent runs sit beside it: mode, who started it, the ticket and the outcome.", 0.75, 6.75, 11.8, size=12)

s, x, ih = step_slide(None, "Add a headend", "The same shape of form for the other direction: a new ACME headend, linked to every branch you choose.",
                  "portal-add-headend", "Every value suggested — identity, WAN link, firewall ports and a tunnel per branch", img_w=7.9)
side_note(s, x, h=ih, items=["A headend is the heavier job (about twenty minutes): a new router, a new firewall link, and a tunnel added at both ends of every branch it serves.",
                 "The wizard allocates the tunnel numbers and /30s for each branch at once, so the mesh stays consistent.",
                 "The same pipeline runs it, and the same tests prove it."], title="The other direction")

two_up_slide("Change a branch, safely",
             "Day-two work is a short job with a narrow blast radius — one branch, one property, one ticket.",
             "portal-change-auth", "portal-task-pick",
             "Change IKE authentication — pre-shared key ↔ certificate from the lab CA",
             "Every per-branch task starts by asking which router",
             ["Moving a branch to certificates re-enrols it with the CA, swaps the IKEv2 profile, keyring and trustpoint, clears the security associations and waits for every tunnel to re-authenticate — nine steps, and the tests at the end.",
              "Rotating a pre-shared key is the same idea in five minutes: a new key on the branch and on every headend that serves it, then the SAs are cleared and the tunnels verified."])

s, x, ih = step_slide(None, "Remove a branch", "Decommissioning says what it is about to delete before it deletes anything — and needs an approver.",
                  "portal-remove", "The confirmation lists the router, the tunnels, the Nautobot objects and the Terraform state that will go", img_w=7.4)
side_note(s, x, h=ih, items=["Only a user with the approver role may start it; an operator sees the card but cannot run it.",
                 "The reverse of provisioning, in the same order: tunnels dropped at both ends, objects removed from Nautobot, lab.conf and Terraform state cleaned, the VM deleted.",
                 "The job and its log stay in the ledger afterwards."], title="Guarded by design")

s, x, ih = step_slide(None, "The ledger: every job the portal has run", "Jobs is the operational record — what ran, against what, by whom, for how long, and whether the tests passed.",
                  "portal-jobs", "Filterable by status, job type and target; a failed job offers Resume", img_w=8.1, img_h=4.3)
side_note(s, 9.3, h=ih, items=["Thirty jobs kept · twenty-five succeeded · seventy-four tests run in them — the portal's own counters.",
                   "Every row carries its change ticket, so the record matches the change-management system.",
                   "A failed job keeps its successful steps and offers Resume rather than a fresh start."], title="The record")

s, x, ih = step_slide(None, "The service as it stands", "Home is the daily view: capacity and health first, the live topology below it.",
                  "portal-inventory", "Tunnels up, headend CPU, firewall bandwidth and free tunnel slots — then the map, coloured by live state", img_w=8.2)
side_note(s, x, h=ih, items=["Every tile is collected from the routers and the firewalls, with the time of collection shown; nothing is cached silently.",
                 "The topology is drawn from Nautobot and coloured live: a degraded tunnel is visible before anyone reports it.",
                 "Free tunnel slots and spare firewall bandwidth are the numbers that decide whether the next branch fits."], title="Capacity, not guesswork")

s, x, ih = step_slide(None, "Drift, and what to do about it", "Golden Config renders the intended configuration from Nautobot and compares it with what each router is actually running.",
                  "portal-compliance", "Per-device compliance with the differences, remediation and re-apply as jobs of their own", img_w=8.2)
side_note(s, x, h=ih, items=["A scheduled run keeps the comparison current; the page shows when it last ran and what it found.",
                 "Remediate pushes only the difference; Re-apply pushes the whole intended configuration — both are ordinary jobs with logs and tests.",
                 "Drift history is kept, so 'when did this device start differing?' has an answer."], title="Two ways back")

close_slide()

# ---------------------------------------------------------------- render
def hexc(c): return RGBColor.from_string(c)


def build_pptx():
    prs = Presentation(); prs.slide_width, prs.slide_height = Inches(W), Inches(H)
    blank = prs.slide_layouts[6]
    for sp in slides:
        sl = prs.slides.add_slide(blank)
        bg = sl.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(W), Inches(H))
        bg.fill.solid(); bg.fill.fore_color.rgb = hexc(sp["bg"]); bg.line.fill.background(); bg.shadow.inherit = False
        for it in sp["items"]:
            if it["k"] == "box":
                sh = sl.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if it["radius"] else MSO_SHAPE.RECTANGLE,
                                         Inches(it["x"]), Inches(it["y"]), Inches(it["w"]), Inches(it["h"]))
                if it["radius"]: sh.adjustments[0] = min(0.5, it["radius"] * 2 / max(it["w"], it["h"]))
                sh.fill.solid(); sh.fill.fore_color.rgb = hexc(it["fill"])
                sh.line.color.rgb = hexc(it["line"]); sh.line.width = Pt(it["lw"]); sh.shadow.inherit = False
            elif it["k"] == "circle":
                sh = sl.shapes.add_shape(MSO_SHAPE.OVAL, Inches(it["x"]), Inches(it["y"]), Inches(it["w"]), Inches(it["h"]))
                sh.fill.solid(); sh.fill.fore_color.rgb = hexc(it["fill"]); sh.line.fill.background(); sh.shadow.inherit = False
            elif it["k"] == "img":
                sl.shapes.add_picture(it["src"], Inches(it["x"]), Inches(it["y"]), Inches(it["w"]), Inches(it["h"]))
            elif it["k"] == "text":
                tb = sl.shapes.add_textbox(Inches(it["x"]), Inches(it["y"]), Inches(it["w"]), Inches(it["h"]))
                tf = tb.text_frame; tf.word_wrap = True
                tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
                tf.vertical_anchor = {"t": MSO_ANCHOR.TOP, "m": MSO_ANCHOR.MIDDLE}[it["anchor"]]
                for i, p in enumerate(it.get("paras", [])):
                    par = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
                    par.alignment = {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER}[it["align"]]
                    par.line_spacing = it["spacing"]; par.space_after = Pt(p["space_after"])
                    run = par.add_run(); run.text = p["txt"]
                    f = run.font; f.name = it["font"]; f.size = Pt(p["size"]); f.bold = p["bold"]; f.italic = p["italic"]
                    f.color.rgb = hexc(p["color"])
    prs.save(OUT)
    return OUT


def build_preview():
    """The same geometry as HTML, so a browser can show what the deck looks like."""
    px = 96
    out = ["<!doctype html><meta charset='utf-8'><style>",
           f"body{{margin:0;background:#33383f;font-family:Calibri,Carlito,sans-serif}}",
           f".s{{position:relative;width:{W*px}px;height:{H*px}px;margin:18px auto;overflow:hidden}}",
           ".i{position:absolute}", ".t{white-space:pre-wrap}", "</style>"]
    for n, sp in enumerate(slides, 1):
        out.append(f"<div class='s' style='background:#{sp['bg']}' id='s{n}'>")
        for it in sp["items"]:
            st = f"left:{it['x']*px}px;top:{it['y']*px}px;width:{it['w']*px}px;height:{it['h']*px}px"
            if it["k"] == "box":
                out.append(f"<div class='i' style='{st};background:#{it['fill']};border:{it['lw']}px solid #{it['line']};"
                           f"border-radius:{it['radius']*px}px;box-sizing:border-box'></div>")
            elif it["k"] == "circle":
                out.append(f"<div class='i' style='{st};background:#{it['fill']};border-radius:50%'></div>")
            elif it["k"] == "img":
                out.append(f"<img class='i' style='{st}' src='{it['src']}'>")
            elif it["k"] == "text":
                al = {"l": "left", "c": "center"}[it["align"]]
                fam = "Cambria, 'Caladea', serif" if it["font"] == "Cambria" else "Calibri, Carlito, sans-serif"
                inner = "".join(
                    f"<div style='font-size:{p['size']}pt;color:#{p['color']};font-weight:{700 if p['bold'] else 400};"
                    f"font-style:{'italic' if p['italic'] else 'normal'};line-height:{it['spacing']};"
                    f"margin-bottom:{p['space_after']}pt'>{htmlmod.escape(p['txt'])}</div>" for p in it.get("paras", []))
                out.append(f"<div class='i t' style='{st};text-align:{al};font-family:{fam};"
                           f"display:flex;flex-direction:column;justify-content:{'center' if it['anchor'] == 'm' else 'flex-start'}'>{inner}</div>")
        out.append(f"<div style='position:absolute;right:10px;bottom:6px;font-size:9pt;color:#9aa4b2'>{n}</div></div>")
    p = HERE / "portal-workflows-preview.html"
    p.write_text("\n".join(out), encoding="utf-8")
    return p


if __name__ == "__main__":
    prev = build_preview()
    print(f"preview: {prev}  ({len(slides)} slides)")
    if "--preview" not in sys.argv:
        f = build_pptx()
        print(f"deck: {f} ({f.stat().st_size / 1e6:.1f} MB, {len(slides)} slides)")
