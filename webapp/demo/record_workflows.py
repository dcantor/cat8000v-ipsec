#!/usr/bin/env python3
"""Record demo/portal-workflows.mp4 — the moving version of docs/portal-workflows.pptx, beat for beat.

The deck is fifteen stills of the portal with an explanation beside each; this is the same walkthrough against the live
portal, so the reviewer sees the forms fill themselves in, the wizard step forward and a finished job's steps stream.
It is strictly read-only: every dialog is cancelled and no job is started on the lab.

Usage: record_workflows.py [--url http://localhost:8090] [--user admin] [--password admin] [--out webapp/demo/]"""
import argparse
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from demolib import Recorder                                          # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("--url", default="http://localhost:8090")
p.add_argument("--out", default=str(Path(__file__).resolve().parent))
p.add_argument("--width", type=int, default=1400); p.add_argument("--height", type=int, default=860)
p.add_argument("--user", default="admin"); p.add_argument("--password", default="admin")
p.add_argument("--no-gif", action="store_true")
a = p.parse_args()
OUT = Path(a.out); OUT.mkdir(parents=True, exist_ok=True)
R = Recorder(a.width, a.height)

# The deck's palette, so the card slides and the .pptx are visibly the same document.
INK, ACCENT, NAVY, PALE, MUTED = "#0B1020", "#C2410C", "#1B2A4A", "#C7D2E4", "#8FA3BF"
CARD_CSS = f"""
 * {{ box-sizing: border-box }}
 body {{ margin:0; width:{a.width}px; height:{a.height}px; background:{INK}; color:#fff;
         font-family: Calibri, Carlito, system-ui, sans-serif; display:flex; flex-direction:column;
         justify-content:center; padding:0 72px }}
 h1 {{ font-family: Cambria, Caladea, serif; font-size:52px; margin:0 0 14px; font-weight:700 }}
 .sub {{ font-size:23px; color:{PALE}; margin-bottom:26px }}
 .meta {{ font-size:15px; color:{MUTED}; line-height:1.5 }}
 .dot {{ position:absolute; right:96px; top:236px; width:150px; height:150px; border-radius:50%;
         background:{ACCENT}; display:flex; align-items:center; justify-content:center;
         font-family:Cambria,Caladea,serif; font-size:44px; font-weight:700 }}
 .dotl {{ position:absolute; right:60px; top:398px; width:222px; text-align:center; font-size:14px; color:{PALE} }}
 .cols {{ display:flex; gap:26px; margin:30px 0 34px }}
 .col {{ flex:1; background:{NAVY}; border-radius:10px; padding:26px 24px }}
 .col h3 {{ font-family:Cambria,Caladea,serif; font-size:21px; margin:0 0 12px }}
 .col p {{ font-size:15px; line-height:1.45; color:{PALE}; margin:0 }}
"""


def card(page, body, seconds=4.0):
    """A title / closing slide, drawn in the same browser so it encodes identically to the portal frames."""
    page.set_content(f"<!doctype html><meta charset='utf-8'><style>{CARD_CSS}</style>{body}")
    time.sleep(0.4); R.hold(page, seconds)


with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome", headless=True)
    ctx = browser.new_context(viewport={"width": a.width, "height": a.height})
    page = ctx.new_page(); page.on("dialog", lambda d: d.accept())

    # ---- title ---------------------------------------------------------------------------------------------------
    card(page, f"""<h1>The VPN Provisioning Portal</h1>
      <div class='sub'>An executive overview of the workflows &mdash; every screen an operator touches, in order</div>
      <div class='meta'>Managed IPsec VPN service &middot; Catalyst 8000v VTI + eBGP &middot; Nautobot source of truth<br>
      Network-as-Code (Terraform) &middot; Robot Framework validation</div>
      <div class='dot'>12</div><div class='dotl'>workflows, one screen</div>""", 4.5)

    page.goto(a.url + "/#provision"); page.wait_for_selector("#login-form"); time.sleep(0.8)
    R.caption(page, "Sign in — the role decides what you may start",
              "viewer reads · operator provisions and changes · approver also removes a branch · single sign-on via OpenID Connect")
    R.hold(page, 3.0)
    el = R.move_to(page, "#login-user"); el.click(); el.fill(""); el.type(a.user, delay=45); R.snap(page, 0.8)
    el = R.move_to(page, "#login-pass"); el.click(); el.fill(""); el.type(a.password, delay=45); R.snap(page, 0.8)
    R.click(page, "#login-go", settle=2.2)
    page.wait_for_selector("#devices tbody tr")
    # the header's "N routers onboarded" only lands once Nautobot has answered; until then it still reads "unreachable"
    page.wait_for_function("(document.getElementById('inv-note').textContent || '').includes('onboarded')", timeout=120000)
    time.sleep(1.2)

    # ---- 2. the launcher -----------------------------------------------------------------------------------------
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.4)
    R.caption(page, "One screen: “what do you want to do?”",
              "the Provision tab opens on the task, not on a form — each card says what the job does, how long it takes and who may start it")
    R.hold(page, 4.0)
    R.note(page, ".task >> nth=0", "Build: a branch or a headend — the full pipeline, about fifteen minutes"); R.hold(page, 3.0); R.note_off(page)
    R.note(page, ".task:has-text('Remove a branch')", "each card carries its own duration and the role it needs — an approver, before anything is removed"); R.hold(page, 3.0); R.note_off(page)
    page.evaluate("document.getElementById('launcher').scrollIntoView({block:'start'}); window.scrollBy(0, 260)"); time.sleep(0.6)
    R.caption(page, "Every change is a job", "the whole service · configuration drift · and the service model itself, all from the same list", numbered=False)
    R.hold(page, 3.0)

    # ---- 3. add a branch, step 1 ---------------------------------------------------------------------------------
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.3)
    R.caption(page, "Add a branch — who it is", "step 1 of 3: identity, the customer, and the headends this branch will reach; the fields it can work out, it fills in")
    R.click(page, "#add-spoke", settle=2.0)
    R.hold(page, 2.5)
    R.note(page, "#sp\\.city", "a catalogue city places the branch on the map — Nautobot location coordinates"); R.hold(page, 2.5); R.note_off(page)
    R.scroll_to(page, "#sp\\.customer\\.company", "center")
    R.note(page, "#sp\\.customer\\.company", "every branch is a customer of ACME: company, tier, account — a Nautobot tenant"); R.hold(page, 3.0); R.note_off(page)
    el = R.move_to(page, "#sp\\.comments"); el.click(); el.fill(""); el.type("branch office 6 - walkthrough", delay=30); R.snap(page, 1.0)
    R.caption(page, "Nothing is created yet", "the portal checks the name is free in Nautobot and in the lab; cancel costs nothing", numbered=False)
    R.hold(page, 2.5)

    # ---- 4. step 2: allocation ------------------------------------------------------------------------------------
    R.caption(page, "Add a branch — where it lives",
              "step 2 of 3: router-id, LAN, AS number, firewall ports, WAN /30s and tunnel numbers — every value the next free one, and editable")
    R.click(page, "#wiz-next", settle=3.0)
    R.hold(page, 4.0)
    page.mouse.wheel(0, 320); time.sleep(0.5); R.hold(page, 3.0)
    R.caption(page, "Capacity is part of the form",
              "each headend line shows the free ports on its firewall and how many tunnel slots remain; change a value and it is re-validated against the live lab", numbered=False)
    R.hold(page, 3.0)

    # ---- 5. step 3: review ----------------------------------------------------------------------------------------
    R.caption(page, "Add a branch — confirm, then provision",
              "step 3 of 3: the whole change in one place — what will be created, on which devices, under which change ticket")
    R.click(page, "#wiz-next", settle=3.0)
    R.hold(page, 4.0)
    page.mouse.wheel(0, 420); time.sleep(0.5); R.hold(page, 3.0)
    R.caption(page, "One button, one job",
              "VM, onboarding, Nautobot, Terraform on both ends, then the tests — about fifteen minutes later the branch is carrying traffic (cancelled here: this is a read-only walkthrough)", numbered=False)
    R.hold(page, 3.5); R.click(page, "#wiz-cancel")

    # ---- 6. the run ------------------------------------------------------------------------------------------------
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.3)
    runs = page.evaluate("async () => (await (await fetch('/api/runs')).json())")
    ok = next((r for r in runs if r["status"] == "success" and r["mode"] in ("spoke", "hub")), runs[0])
    R.scroll_to(page, "#runcard")
    page.evaluate("id => watchInline(id)", ok["id"]); time.sleep(2.5)
    page.evaluate("document.getElementById('runcard').scrollIntoView({block:'start'})"); time.sleep(0.6)
    R.caption(page, "Add a branch — watch it run",
              "validate intent → save intent → seed Nautobot → render the NaC data → Terraform plan → apply → tests; each step says what it actually changed")
    R.hold(page, 5.0)
    page.mouse.wheel(0, 380); time.sleep(0.5)
    R.caption(page, "Recent runs sit beside it", "mode, who started it, the change ticket and the outcome — one job at a time, so two changes can never race on the same router", numbered=False)
    R.hold(page, 3.5)

    # ---- 7. the job page -------------------------------------------------------------------------------------------
    job = next((r for r in runs if r.get("tests")), ok)
    page.goto(a.url + f"/#job/{job['id']}")
    page.wait_for_function("document.querySelectorAll('#job-steps li').length > 0", timeout=90000); time.sleep(2.0)
    R.caption(page, "Every job looks the same",
              "its own page: the steps, the live log, the test report and the ticket — a failed job resumes from the failed step, it does not start again")
    R.hold(page, 4.5)
    page.mouse.wheel(0, 520); time.sleep(0.6); R.hold(page, 3.5)

    # ---- 8. add a headend -------------------------------------------------------------------------------------------
    page.goto(a.url + "/#provision"); page.wait_for_selector("#devices tbody tr"); time.sleep(1.0)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.3)
    R.caption(page, "Add a headend — the other direction",
              "the same shape of form for a new ACME headend: its VM, a WAN link through the firewall, and a tunnel added at both ends of every branch it serves")
    R.click(page, "#add-hub", settle=1.0)
    page.wait_for_function("document.getElementById('hub-name').value !== ''", timeout=90000); time.sleep(1.0)
    R.snap(page, 1.0); R.hold(page, 4.0)
    page.mouse.wheel(0, 360); time.sleep(0.5)
    R.caption(page, "The mesh stays consistent", "the wizard allocates the tunnel numbers and /30s for every branch at once; the same pipeline runs it and the same tests prove it", numbered=False)
    R.hold(page, 3.0); R.click(page, "#hub-cancel")

    # ---- 9. change a branch, safely ----------------------------------------------------------------------------------
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.3)
    R.caption(page, "Change a branch, safely",
              "day-two work is a short job with a narrow blast radius — one branch, one property, one ticket; every per-branch task starts by asking which router")
    page.evaluate("pickRouter('rotate')"); time.sleep(1.0); R.snap(page, 1.2); R.hold(page, 3.5)
    R.click(page, "#pick-cancel")
    R.scroll_to(page, "#devices")
    R.note(page, "#devices button.auth >> nth=0", "Change auth…: pre-shared key ↔ a certificate from the lab CA"); R.hold(page, 2.5); R.note_off(page)
    R.click(page, "#devices button.auth >> nth=0", settle=2.0)
    R.caption(page, "Change IKE authentication",
              "re-enrols the branch with the CA, swaps the IKEv2 profile, keyring and trustpoint, clears the security associations and waits for every tunnel to re-authenticate — nine steps, then the tests")
    R.hold(page, 4.5); R.click(page, "#auth-cancel")

    # ---- 10. remove a branch ------------------------------------------------------------------------------------------
    R.scroll_to(page, "#devices")
    R.caption(page, "Remove a branch — guarded by design",
              "decommissioning says what it is about to delete before it deletes anything, and only an approver may start it")
    R.click(page, "#devices button.rm >> nth=-1", settle=2.0)
    R.hold(page, 4.5)
    R.caption(page, "The reverse of provisioning, in the same order",
              "tunnels dropped at both ends, objects removed from Nautobot, lab.conf and Terraform state cleaned, the VM deleted — the job and its log stay in the ledger", numbered=False)
    R.hold(page, 3.0); R.click(page, "#rm-cancel")

    # ---- 11. the ledger --------------------------------------------------------------------------------------------
    page.goto(a.url + "/#jobs")
    page.wait_for_function("document.querySelectorAll('#jobs-table tbody tr').length > 0", timeout=90000); time.sleep(1.2)
    R.caption(page, "The ledger: every job the portal has run",
              "what ran, against what, by whom, for how long, and whether the tests passed — filterable by status, job type and target")
    R.hold(page, 4.5)
    page.mouse.wheel(0, 420); time.sleep(0.5)
    R.caption(page, "The record matches change management", "every row carries its change ticket; a failed job keeps its successful steps and offers Resume", numbered=False)
    R.hold(page, 3.0)

    # ---- 12. the service as it stands -------------------------------------------------------------------------------
    page.goto(a.url + "/#home")
    page.wait_for_function("document.querySelectorAll('#inv-kpis .kpi').length > 0", timeout=240000); time.sleep(1.5)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.4)
    R.caption(page, "The service as it stands",
              "Home is the daily view: tunnels up, headend CPU, firewall bandwidth and free tunnel slots — every tile collected from the routers, with the time it was read")
    R.hold(page, 4.5)
    page.evaluate("document.getElementById('inv-topo').scrollIntoView({block:'start'})"); time.sleep(1.0)
    R.caption(page, "The topology, coloured live",
              "drawn from Nautobot and coloured by live state — a degraded tunnel is visible here before anyone reports it", numbered=False)
    R.hold(page, 4.5)
    page.evaluate("const e = document.getElementById('inv-capacity'); if (e) e.parentElement.scrollIntoView({block:'start'})"); time.sleep(0.8)
    R.caption(page, "Capacity, not guesswork", "free tunnel slots and spare firewall bandwidth are the numbers that decide whether the next branch fits", numbered=False)
    R.hold(page, 3.5)

    # ---- 13. drift ------------------------------------------------------------------------------------------------
    page.goto(a.url + "/#compliance")
    page.wait_for_function("document.querySelectorAll('#cmp-table tbody tr').length > 0", timeout=120000); time.sleep(1.0)
    R.caption(page, "Drift, and what to do about it",
              "Golden Config renders the intended configuration from Nautobot and compares it with what each router is actually running")
    R.hold(page, 4.5)
    page.mouse.wheel(0, 400); time.sleep(0.5)
    R.caption(page, "Two ways back",
              "Remediate pushes only the difference; Re-apply pushes the whole intended configuration — both are ordinary jobs, with logs, tests and a drift history", numbered=False)
    R.hold(page, 4.0)

    # ---- closing ---------------------------------------------------------------------------------------------------
    card(page, f"""<h1>What the UI is for</h1>
      <div class='cols'>
        <div class='col'><h3>Anyone can run it</h3><p>The knowledge is in the forms, not in an engineer's head: every value is
          suggested from the model and validated against the live lab before anything is applied.</p></div>
        <div class='col'><h3>Nothing happens off the record</h3><p>Sign-in, role, change ticket, the steps, the log and the test
          report are kept with the job. The audit page lists every action the portal took.</p></div>
        <div class='col'><h3>The model stays true</h3><p>Golden Config compares the routers against what Nautobot says they
          should be; drift is visible on one page and remediated as a job of its own.</p></div>
      </div>
      <div class='meta'>Provision to start a job &middot; Jobs to see every one that has run &middot; Home for the service as it stands<br>
      The full specification (115 requirements) is docs/requirements.pdf; these slides are docs/portal-workflows.pptx.</div>""", 5.5)

    ctx.close(); browser.close()

mp4 = R.write_mp4(OUT / "portal-workflows.mp4")
secs = sum(d for _, d in R.frames)
print(f"{mp4} ({mp4.stat().st_size / 1e6:.1f} MB, {len(R.frames)} frames, {secs / 60:.1f} min, {R.scene} scenes)")
if not a.no_gif:
    gif, g = R.write_gif(OUT / "portal-workflows.gif")
    print(f"{gif} ({gif.stat().st_size / 1e6:.1f} MB, {g:.0f}s)")
