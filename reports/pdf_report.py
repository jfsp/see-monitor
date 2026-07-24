#!/usr/bin/env python3
"""
SEE-Monitor: PDF Report Generator

Produces two shareable PDF reports, both profile-aware (colours/labels come
from the selected guideline's rating bands):

  * build_scope_report_pdf() — header + status distribution + KPIs +
    per-domain table + an embedded trend chart.
  * build_trend_report_pdf() — the trend chart + a per-period detail table.

reportlab is the only extra runtime dependency (pure-Python, no system libs).
It is imported here (not at package import time) so the rest of the app runs
without it; the routes surface a clear 501 if it is missing.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import io

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.graphics.shapes import Drawing, Rect, Line, PolyLine, String, Circle

CONTENT_W = A4[0] - 40 * mm          # usable width inside 20mm margins
ACCENT = HexColor("#4a90d9")
INK = HexColor("#1a2029")
MUTED = HexColor("#8a97a8")

_FALLBACK = {
    "not_implemented": ("Not implemented", "#d64545"),
    "medium": ("Medium", "#e0a030"),
    "strong": ("Strong", "#4a90d9"),
    "very_strong": ("Very strong", "#3aa76d"),
    "partial": ("Partial", "#e0a030"),
    "compliant": ("Compliant", "#3aa76d"),
}


def _rating_meta(bands):
    """Return (order_worst_first, label_map, color_map) from guideline bands."""
    if bands:
        ordered = sorted(bands, key=lambda b: b.get("min_score", 0))
        order = [b["rating"] for b in ordered]
        labels = {b["rating"]: b.get("label", b["rating"]) for b in ordered}
        colmap = {b["rating"]: b.get("color", "#888888") for b in ordered}
    else:
        order = ["not_implemented", "medium", "strong", "very_strong"]
        labels = {r: _FALLBACK[r][0] for r in order}
        colmap = {r: _FALLBACK[r][1] for r in order}
    for r, (lbl, col) in _FALLBACK.items():        # fill any gaps
        labels.setdefault(r, lbl)
        colmap.setdefault(r, col)
    return order, labels, colmap


def _hx(c):
    try:
        return HexColor(c)
    except Exception:
        return MUTED


# ----------------------------------------------------------------------
# Drawings
# ----------------------------------------------------------------------
def _status_bar_drawing(ratings, order, colmap, width=CONTENT_W, height=22):
    d = Drawing(width, height)
    total = sum(ratings.get(r, 0) for r in order)
    if not total:
        d.add(Rect(0, 0, width, height, fillColor=HexColor("#eef1f4"),
                   strokeColor=MUTED))
        d.add(String(6, height / 2 - 3, "No assessments in scope",
                     fontSize=8, fillColor=MUTED))
        return d
    x = 0
    for r in order:                                # worst -> best, left -> right
        n = ratings.get(r, 0)
        if not n:
            continue
        w = width * n / total
        d.add(Rect(x, 0, w, height, fillColor=_hx(colmap[r]),
                   strokeColor=colors.white, strokeWidth=0.5))
        if w > 22:
            d.add(String(x + w / 2, height / 2 - 3.5, str(n),
                         fontSize=8, fillColor=colors.white,
                         textAnchor="middle"))
        x += w
    return d


def _trend_drawing(buckets, order, colmap, width=CONTENT_W, height=190):
    d = Drawing(width, height)
    padL, padR, padT, padB = 30, 30, 12, 40
    plotW, plotH = width - padL - padR, height - padT - padB
    yB = padB
    if not buckets:
        d.add(String(width / 2, height / 2, "No assessment history in scope",
                     fontSize=9, fillColor=MUTED, textAnchor="middle"))
        return d
    n = len(buckets)
    bandW = plotW / n
    barW = min(bandW * 0.6, 34)
    max_total = 1
    for b in buckets:
        t = sum((b.get("ratings") or {}).values())
        max_total = max(max_total, t)

    def cx(i):
        return padL + bandW * (i + 0.5)

    def y_count(v):
        return yB + (v / max_total) * plotH

    def y_score(v):
        return yB + (v / 100.0) * plotH

    # gridlines + left (count) axis
    for i in range(5):
        v = round(max_total * i / 4)
        y = y_count(v)
        d.add(Line(padL, y, padL + plotW, y,
                   strokeColor=HexColor("#e2e6ea"), strokeWidth=0.5))
        d.add(String(padL - 4, y - 3, str(v), fontSize=7,
                     fillColor=MUTED, textAnchor="end"))
    # right (score) axis
    for v in (0, 50, 100):
        y = y_score(v)
        d.add(String(padL + plotW + 4, y - 3, str(v), fontSize=7,
                     fillColor=ACCENT, textAnchor="start"))
    d.add(Line(padL, yB, padL + plotW, yB, strokeColor=MUTED, strokeWidth=0.7))

    # stacked bars
    for i, b in enumerate(buckets):
        acc = 0
        for r in order:
            v = (b.get("ratings") or {}).get(r, 0)
            if not v:
                continue
            y0, y1 = y_count(acc), y_count(acc + v)
            d.add(Rect(cx(i) - barW / 2, y0, barW, y1 - y0,
                       fillColor=_hx(colmap[r]), strokeColor=colors.white,
                       strokeWidth=0.4))
            acc += v

    # score line + dots
    pts = []
    for i, b in enumerate(buckets):
        pts += [cx(i), y_score(b.get("avg_score", 0))]
    if len(pts) >= 4:
        d.add(PolyLine(pts, strokeColor=ACCENT, strokeWidth=1.5))
    for i, b in enumerate(buckets):
        d.add(Circle(cx(i), y_score(b.get("avg_score", 0)), 2.2,
                     fillColor=ACCENT, strokeColor=ACCENT))

    # x labels (thinned)
    step = max(1, (n + 11) // 12)
    for i, b in enumerate(buckets):
        if i % step:
            continue
        d.add(String(cx(i), yB - 12, str(b.get("label", "")), fontSize=6.5,
                     fillColor=MUTED, textAnchor="middle"))
    return d


# ----------------------------------------------------------------------
# Shared building blocks
# ----------------------------------------------------------------------
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Title"], fontSize=18,
                          textColor=INK, spaceAfter=2))
    ss.add(ParagraphStyle("Subx", parent=ss["Normal"], fontSize=9,
                          textColor=MUTED, spaceAfter=10))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], fontSize=11,
                          textColor=INK, spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle("Cap", parent=ss["Normal"], fontSize=8,
                          textColor=MUTED))
    return ss


def _header(meta, ss):
    scope = meta.get("scope_label", "all domains")
    gname = meta.get("guideline_name", meta.get("guideline_id", ""))
    return [
        Paragraph("SEE-Monitor — Email Security Report", ss["H1x"]),
        Paragraph(
            f"Scope: <b>{scope}</b> &nbsp;·&nbsp; Standard: <b>{gname}</b>"
            f" &nbsp;·&nbsp; Generated: {meta.get('generated_at','')}",
            ss["Subx"]),
    ]


def _legend_table(ratings, order, labels, colmap, total):
    rows, style = [], [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
    ]
    for i, r in enumerate(reversed(order)):        # best first
        n = ratings.get(r, 0)
        if not n:
            continue
        pct = round(100 * n / total) if total else 0
        rows.append(["", f"{labels[r]}", str(n), f"{pct}%"])
        style.append(("BACKGROUND", (0, len(rows) - 1), (0, len(rows) - 1),
                      _hx(colmap[r])))
    if not rows:
        return None
    t = Table(rows, colWidths=[10, 160, 40, 40], hAlign="LEFT")
    t.setStyle(TableStyle(style))
    return t


def _kpi_table(meta, order, labels, ss):
    total = meta.get("total", 0)
    avg = meta.get("avg_score", 0)
    ratings = meta.get("ratings", {})
    top = list(reversed(order))[0] if order else None
    good = ratings.get(top, 0) if top else 0
    pct = round(100 * good / total) if total else 0
    data = [[
        Paragraph(f"<b>{total}</b>", ss["H1x"]),
        Paragraph(f"<b>{avg}</b> <font size=8>/100</font>", ss["H1x"]),
        Paragraph(f"<b>{good}</b> <font size=8>({pct}%)</font>", ss["H1x"]),
    ], [
        Paragraph("Domains assessed", ss["Cap"]),
        Paragraph("Average score", ss["Cap"]),
        Paragraph(f"{labels.get(top, top or '')}", ss["Cap"]),
    ]]
    t = Table(data, colWidths=[CONTENT_W / 3] * 3)
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#d7dde3")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#d7dde3")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _pdf(elements) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="SEE-Monitor Report")
    doc.build(elements)
    return buf.getvalue()


# ----------------------------------------------------------------------
# Public builders
# ----------------------------------------------------------------------
def build_scope_report_pdf(meta, assessments, buckets, bands) -> bytes:
    order, labels, colmap = _rating_meta(bands)
    ss = _styles()
    ratings = meta.get("ratings", {})
    total = meta.get("total", 0)

    el = _header(meta, ss)
    el.append(_kpi_table(meta, order, labels, ss))
    el.append(Spacer(1, 10))
    el.append(Paragraph("Status distribution", ss["H2x"]))
    el.append(_status_bar_drawing(ratings, order, colmap))
    lg = _legend_table(ratings, order, labels, colmap, total)
    if lg:
        el.append(Spacer(1, 4))
        el.append(lg)

    if buckets:
        el.append(Paragraph("Score & status trend", ss["H2x"]))
        el.append(Paragraph(
            "Bars: domain count per status · Line: average score (0–100)",
            ss["Cap"]))
        el.append(_trend_drawing(buckets, order, colmap))

    el.append(Paragraph(f"Domains ({len(assessments)})", ss["H2x"]))
    rows = [["Domain", "Score", "Rating"]]
    for a in sorted(assessments, key=lambda x: x.get("score", 0)):
        rows.append([a.get("domain", ""), str(a.get("score", "")),
                     labels.get(a.get("rating"), a.get("rating", ""))])
    tbl = Table(rows, colWidths=[CONTENT_W - 140, 60, 80], repeatRows=1)
    tstyle = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, HexColor("#f4f6f8")]),
        ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#d7dde3")),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, a in enumerate(sorted(assessments, key=lambda x: x.get("score", 0)),
                          start=1):
        tstyle.append(("TEXTCOLOR", (2, i), (2, i),
                       _hx(colmap.get(a.get("rating"), "#333333"))))
    tbl.setStyle(TableStyle(tstyle))
    el.append(tbl)
    return _pdf(el)


def build_trend_report_pdf(meta, buckets, bands) -> bytes:
    order, labels, colmap = _rating_meta(bands)
    ss = _styles()
    el = _header(meta, ss)
    el.append(Paragraph(
        f"Trend — {meta.get('period','weekly')} "
        f"({len(buckets)} period(s))", ss["H2x"]))
    el.append(Paragraph(
        "Bars: domain count per status · Line: average score (0–100)",
        ss["Cap"]))
    el.append(_trend_drawing(buckets, order, colmap))

    el.append(Paragraph("Per-period detail", ss["H2x"]))
    rows = [["Period", "Avg score", "Domains", "Scans", "Status mix"]]
    for b in reversed(buckets):
        mix = " · ".join(
            f"{labels.get(r, r)} {b['ratings'][r]}"
            for r in reversed(order) if (b.get("ratings") or {}).get(r))
        rows.append([b.get("label", ""), str(b.get("avg_score", "")),
                     str(b.get("domains", "")), str(b.get("scans", "")), mix])
    tbl = Table(rows, colWidths=[70, 55, 50, 45, CONTENT_W - 220],
                repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, HexColor("#f4f6f8")]),
        ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#d7dde3")),
        ("ALIGN", (1, 0), (3, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    el.append(tbl)
    return _pdf(el)
