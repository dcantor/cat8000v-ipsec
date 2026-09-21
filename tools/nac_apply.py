#!/usr/bin/env python3
"""Staged Terraform apply for the NaC data: creates first, then updates, then everything else (the destroys).

The iosxe NaC module has no dependency edge from a tunnel interface to the IPsec / IKEv2 profile it references, so in one apply
a VTI can be pushed before its new profile exists ("Device refused one or more commands"), and an old profile can be deleted
while a tunnel still uses it (IOS refuses). Three stages, each a saved plan applied as shown:
  1. every resource the plan creates (-target, dependencies come along)      -> new crypto profiles, keyrings, tunnels
  2. every resource the plan updates in place                                 -> tunnels re-pointed at their new profile
  3. the full plan                                                             -> the destroys, and anything left
Usage: nac_apply.py [--dry-run]   (from the lab root; runs `./lab.sh nac ...`, which carries the router credentials and saves
the running config after a successful full apply)"""
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]; NAC = LAB / "nac"
BASE = ["-no-color", "-input=false", "-parallelism=1"]


def tf(*args, check=True, capture=False):
    sys.stdout.flush(); r = subprocess.run(["./lab.sh", "nac", *args], cwd=LAB, text=True, capture_output=capture); sys.stdout.flush()
    if check and r.returncode not in (0, 2): sys.exit(f"terraform {args[0]} failed (rc={r.returncode})")
    return r


def plan(out, targets=()):
    r = tf("plan", *BASE, "-detailed-exitcode", f"-out={out}", *[f"-target={t}" for t in targets])
    return r.returncode == 2   # changes pending


def changes(planfile):
    show = subprocess.run(["./lab.sh", "nac", "show", "-json", planfile], cwd=LAB, text=True, capture_output=True, check=True).stdout
    return [(c["address"], c["change"]["actions"]) for c in json.loads(show).get("resource_changes", []) if c.get("mode") == "managed"]


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0]); p.add_argument("--dry-run", action="store_true"); a = p.parse_args()
    with tempfile.TemporaryDirectory() as td:
        full = f"{td}/full.tfplan"
        if not plan(full): print("No changes. Your infrastructure matches the configuration."); return
        ch = changes(full)
        # the module's iosxe_cli templates depend on every other resource: targeting one drags the whole graph into the stage, so they
        # (and the model file) wait for the full plan
        creates = [addr for addr, act in ch if act == ["create"] and not ("local_sensitive_file" in addr or ".iosxe_cli." in addr)]
        updates = [addr for addr, act in ch if act == ["update"] and ".iosxe_cli." not in addr]
        print(f"staged apply: {len(creates)} to create, {len(updates)} to update in place, then the rest ({sum(1 for _, act in ch if 'delete' in act)} to destroy / replace)")
        if a.dry_run:
            for addr, act in ch: print(f"  {'+'.join(act):14s} {addr}")
            return
        for stage, targets in (("stage 1/3: creates", creates), ("stage 2/3: updates", updates)):
            if not targets: print(f"{stage}: nothing"); continue
            pf = f"{td}/{stage[6]}.tfplan"; print(f"==> {stage} ({len(targets)} resources)")
            if plan(pf, targets): tf("apply", *BASE, pf)
        print("==> stage 3/3: the full plan")
        if plan(full): tf("apply", *BASE, full)
        else: print("nothing left to apply")


if __name__ == "__main__": main()
