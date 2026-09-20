#!/usr/bin/env python3
"""Build webapp/static/usa-map.json: the lower-48 state outlines as SVG path strings in a 975x610 canvas, projected with the same
Albers (conic equal-area) parameters d3's geoAlbersUsa uses for the continental US — so the page can place a city with the
identical formula (see `albers()` in static/index.html) and it lands on the right spot of the map.
Source: us-atlas (ISC licence, from the US Census cartographic boundary files) — states-10m.json, TopoJSON in degrees.
    python3 tools/build_usa_map.py [states-10m.json]     (downloads it from jsdelivr when no file is given)"""
import json, math, sys, urllib.request
from pathlib import Path

SRC = "https://cdn.jsdelivr.net/npm/us-atlas@3/states-10m.json"
SKIP = {"02": "Alaska", "15": "Hawaii", "72": "Puerto Rico", "60": "American Samoa", "66": "Guam", "69": "Northern Mariana Islands", "78": "US Virgin Islands"}   # not on the continental canvas
OUT = Path(__file__).resolve().parents[1] / "static" / "usa-map.json"

# d3.geoAlbersUsa's lower-48 component: conic equal-area, parallels 29.5 / 45.5, rotate [96, 0], center [-0.6, 38.7], scale 1070,
# translate [487.5, 305] (the 975 x 610 canvas)
R = math.radians
PHI0, PHI1 = R(29.5), R(45.5); SY0 = math.sin(PHI0); N = (SY0 + math.sin(PHI1)) / 2; C = 1 + SY0 * (2 * N - SY0); R0 = math.sqrt(C) / N
K, TX, TY = 1070, 487.5, 305
def raw(lam, phi):
    r = math.sqrt(C - 2 * N * math.sin(phi)) / N; lam *= N
    return r * math.sin(lam), R0 - r * math.cos(lam)
CX, CY = raw(R(-0.6), R(38.7))
def project(lon, lat):
    x, y = raw(R(lon + 96), R(lat))
    return TX + K * (x - CX), TY - K * (y - CY)   # d3 flips y: screen y grows southwards

def main():
    data = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else json.load(urllib.request.urlopen(SRC, timeout=60))
    sx, sy = data["transform"]["scale"]; tx, ty = data["transform"]["translate"]
    arcs = []
    for arc in data["arcs"]:   # delta-decoded, quantized -> degrees
        x = y = 0; pts = []
        for dx, dy in arc: x += dx; y += dy; pts.append((x * sx + tx, y * sy + ty))
        arcs.append(pts)
    def ring(indexes):
        pts = []
        for i in indexes:
            a = arcs[i] if i >= 0 else arcs[~i][::-1]
            pts += a if not pts else a[1:]
        return pts
    states = []
    for g in data["objects"]["states"]["geometries"]:
        if g["id"] in SKIP: continue
        polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]]
        d = ""
        for poly in polys:
            for r in poly:
                pts = [project(lon, lat) for lon, lat in ring(r)]
                d += "M" + " ".join(f"{x:.1f},{y:.1f}" for x, y in pts) + "Z"
        states.append({"id": g["id"], "name": g["properties"]["name"], "d": d})
    OUT.write_text(json.dumps({"width": 975, "height": 610, "projection": {"type": "albers", "parallels": [29.5, 45.5], "rotate": 96, "center": [-0.6, 38.7], "scale": 1070, "translate": [487.5, 305]},
                               "source": "us-atlas 3 (states-10m), ISC", "states": states}, separators=(",", ":")))
    print(f"wrote {OUT} ({len(states)} states, {OUT.stat().st_size // 1024} KB)")
    for city, lon, lat in (("New York", -74.006, 40.713), ("Chicago", -87.630, 41.878), ("Los Angeles", -118.243, 34.052), ("Seattle", -122.332, 47.606), ("Miami", -80.192, 25.762)):
        print(f"  {city:12s} -> ({project(lon, lat)[0]:.0f}, {project(lon, lat)[1]:.0f})")

if __name__ == "__main__": main()
