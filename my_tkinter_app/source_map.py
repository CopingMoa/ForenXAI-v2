"""Per-file source wiring: which _sources each .md cites and quotes."""
import os
import re
import sys

APP = r"C:\Users\HOME PC\OneDrive\Desktop\Thesis\Final\ForenXAI-v2\my_tkinter_app"
os.chdir(APP)
sys.path.insert(0, APP)

import fetch_knowledge as fk
import services.panels_service as ps


def ident(c):
    d = re.search(r"doi:\s*(\S+?)\.?$", c)
    if d:
        return d.group(1).rstrip(".")
    m = re.search(r"(NIST [\w.\-]+|RFC \d+|A\d\d:\d{4}"
                  r"|OWASP Top 10:\d{4}|Mechatronics)", c)
    return m.group(1) if m else c[:50]


reg = {ident(v["citation"]): k for k, v in fk.SOURCES.items()}
problems = []

print(f"{'file':<40}{'cites':>6}{'quotes':>8}  sources quoted")
print("-" * 100)

for folder in ("incident_response", "interpretability", "datasets",
               "analyst", "features"):
    d = os.path.join("knowledge", folder)
    if not os.path.isdir(d):
        continue
    for name in sorted(os.listdir(d)):
        if not name.endswith(".md"):
            continue
        path = os.path.join(d, name)
        body = open(path, encoding="utf-8").read()

        cites = ps._citations_in(body)
        keys = sorted(set(re.findall(r"#{1,6} From ([\w.\-]+)", body)))

        # Every citation must resolve to a registered source.
        for c in cites:
            if ident(c.split("  [")[0]) not in reg:
                problems.append(f"{folder}/{name}: unregistered citation "
                                f"{c[:60]}")
        # Every quoted key must be registered AND declared in the header.
        cite_keys = {reg[ident(c.split("  [")[0])] for c in cites
                     if ident(c.split("  [")[0]) in reg}
        for k in keys:
            if k not in fk.SOURCES:
                problems.append(f"{folder}/{name}: quotes unregistered {k}")
            elif k not in cite_keys:
                problems.append(f"{folder}/{name}: quotes {k} but does not "
                                f"cite it in the header")
        if not cites and folder != "features":
            problems.append(f"{folder}/{name}: no citation at all")

        print(f"  {folder + '/' + name:<38}{len(cites):>6}{len(keys):>8}  "
              f"{', '.join(keys) if keys else '-'}")

print()
if problems:
    print(f"{len(problems)} PROBLEM(S)")
    for p in problems:
        print("  -", p)
else:
    print("Every .md cites only registered sources, and every quoted source "
          "is declared in its own header.")
sys.exit(len(problems))
