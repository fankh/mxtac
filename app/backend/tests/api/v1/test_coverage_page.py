"""Comprehensive tests for the ATT&CK Coverage page (Feature 16.8).

Coverage page exposes three backend endpoints:
  - GET /api/v1/overview/coverage/heatmap      — 4×9 detection coverage grid
  - GET /api/v1/overview/coverage/tactic-labels — 9 tactic column abbreviations (static)
  - GET /api/v1/coverage                        — rules-based %-summary
                                                  (see test_coverage.py for those tests)

This file tests:
  1. HeatCell.opacity Pydantic computed field (pure schema unit tests)
  2. /api/v1/overview/coverage/tactic-labels — auth, exact content, RBAC
  3. /api/v1/overview/coverage/heatmap — structural invariants, mock fallback,
     DB-driven edge cases, and gap-table compatibility
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# Canonical 9-label order consumed by the frontend heatmap and gap table
_EXPECTED_TACTIC_LABELS = [
    "RECON", "RES", "INIT", "EXEC", "PERS", "PRIV", "DEF-E", "CRED", "DISC"
]

# ATT&CK v14 fixed sub-technique counts per tactic column
_TACTIC_TOTALS = {
    "RECON": 9, "RES": 6,  "INIT": 9,  "EXEC": 14,
    "PERS": 12, "PRIV": 11, "DEF-E": 17, "CRED": 14, "DISC": 13,
}

# ===========================================================================
# 1. Schema unit tests — HeatCell.opacity computed field
# ===========================================================================


def test_heat_cell_opacity_zero_total() -> None:
    """total == 0 → opacity == 0.0 (avoids division by zero)."""
    from app.schemas.overview import HeatCell

    cell = HeatCell(tactic="RECON", covered=0, total=0)
    assert cell.opacity == 0.0


def test_heat_cell_opacity_zero_covered() -> None:
    """covered == 0 with total > 0 → minimum baseline opacity 0.10."""
    from app.schemas.overview import HeatCell

    cell = HeatCell(tactic="RECON", covered=0, total=9)
    assert cell.opacity == 0.10


def test_heat_cell_opacity_full_coverage() -> None:
    """covered == total → maximum opacity 0.85."""
    from app.schemas.overview import HeatCell

    cell = HeatCell(tactic="EXEC", covered=14, total=14)
    assert cell.opacity == 0.85


def test_heat_cell_opacity_partial_coverage() -> None:
    """Partial coverage produces a linearly scaled opacity value."""
    from app.schemas.overview import HeatCell

    cell = HeatCell(tactic="RECON", covered=4, total=9)
    expected = round(0.10 + (4 / 9) * 0.75, 2)
    assert cell.opacity == expected


def test_heat_cell_opacity_always_in_valid_range() -> None:
    """Opacity is always between 0.0 and 0.85 inclusive."""
    from app.schemas.overview import HeatCell

    samples = [
        HeatCell(tactic="RECON", covered=0, total=0),
        HeatCell(tactic="RECON", covered=0, total=9),
        HeatCell(tactic="RECON", covered=5, total=9),
        HeatCell(tactic="EXEC",  covered=14, total=14),
    ]
    for cell in samples:
        assert 0.0 <= cell.opacity <= 0.85, f"Opacity {cell.opacity} out of range for {cell}"


def test_heat_cell_opacity_monotone_increasing() -> None:
    """More coverage → higher opacity (monotone non-decreasing over covered 0..total)."""
    from app.schemas.overview import HeatCell

    opacities = [HeatCell(tactic="CRED", covered=i, total=14).opacity for i in range(15)]
    assert opacities == sorted(opacities), (
        "Opacity must be monotone increasing as coverage increases"
    )


def test_heat_cell_opacity_scale_formula() -> None:
    """Formula: opacity = round(0.10 + (covered/total) * 0.75, 2) when total > 0."""
    from app.schemas.overview import HeatCell

    for covered in range(0, 7):
        total = 6
        cell = HeatCell(tactic="RES", covered=covered, total=total)
        expected = round(0.10 + (covered / total) * 0.75, 2)
        assert cell.opacity == expected, (
            f"covered={covered}/total={total}: got {cell.opacity}, expected {expected}"
        )


# ===========================================================================
# 2. GET /api/v1/overview/coverage/tactic-labels
# ===========================================================================


@pytest.mark.asyncio
async def test_tactic_labels_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_tactic_labels_returns_nine_labels(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Endpoint returns exactly 9 tactic abbreviation labels."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 9


@pytest.mark.asyncio
async def test_tactic_labels_exact_order(client: AsyncClient, auth_headers: dict) -> None:
    """Returns the 9 ATT&CK tactic abbreviations in canonical heatmap column order."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == _EXPECTED_TACTIC_LABELS


@pytest.mark.asyncio
async def test_tactic_labels_all_non_empty_strings(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Every label is a non-empty string."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=auth_headers)
    labels = resp.json()
    assert all(isinstance(lbl, str) and len(lbl) > 0 for lbl in labels)


@pytest.mark.asyncio
async def test_tactic_labels_viewer_role_allowed(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """The viewer role (lowest privilege) can access tactic labels."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=viewer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_tactic_labels_contains_all_nine_expected(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Every expected abbreviation appears in the response."""
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=auth_headers)
    labels = set(resp.json())
    for expected in _EXPECTED_TACTIC_LABELS:
        assert expected in labels, f"Missing tactic label: {expected}"


# ===========================================================================
# 3a. GET /api/v1/overview/coverage/heatmap — auth and structural invariants
# ===========================================================================


@pytest.mark.asyncio
async def test_heatmap_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/overview/coverage/heatmap")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_heatmap_viewer_role_allowed(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """The viewer role can read the coverage heatmap."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=viewer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_heatmap_empty_db_returns_four_rows(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Empty DB triggers mock fallback — response always has 4 technique-family rows."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 4


@pytest.mark.asyncio
async def test_heatmap_each_row_has_nine_cells(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Every row has exactly 9 cells (one per tactic column)."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        assert len(row["cells"]) == 9, (
            f"Row {row['technique_id']} has {len(row['cells'])} cells, expected 9"
        )


@pytest.mark.asyncio
async def test_heatmap_row_technique_ids(client: AsyncClient, auth_headers: dict) -> None:
    """Rows cover exactly the 4 expected technique families."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    ids = {r["technique_id"] for r in resp.json()}
    assert ids == {"T1059", "T1003", "T1021", "T1078"}


@pytest.mark.asyncio
async def test_heatmap_row_indices(client: AsyncClient, auth_headers: dict) -> None:
    """Row indices are 0–3 matching the canonical family order."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    idx = {r["technique_id"]: r["row"] for r in resp.json()}
    assert idx == {"T1059": 0, "T1003": 1, "T1021": 2, "T1078": 3}


@pytest.mark.asyncio
async def test_heatmap_cell_order_matches_tactic_labels(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Cell tactic order in every row matches the /tactic-labels endpoint response."""
    labels_resp = await client.get(
        "/api/v1/overview/coverage/tactic-labels", headers=auth_headers
    )
    heatmap_resp = await client.get(
        "/api/v1/overview/coverage/heatmap", headers=auth_headers
    )
    expected = labels_resp.json()
    for row in heatmap_resp.json():
        assert [c["tactic"] for c in row["cells"]] == expected, (
            f"Row {row['technique_id']} cell order does not match tactic labels"
        )


@pytest.mark.asyncio
async def test_heatmap_covered_never_exceeds_total(
    client: AsyncClient, auth_headers: dict
) -> None:
    """covered ≤ total in every cell (coverage percentage cannot exceed 100 %)."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        for cell in row["cells"]:
            assert cell["covered"] <= cell["total"], (
                f"covered {cell['covered']} > total {cell['total']} "
                f"in {row['technique_id']}/{cell['tactic']}"
            )


@pytest.mark.asyncio
async def test_heatmap_covered_and_total_non_negative(
    client: AsyncClient, auth_headers: dict
) -> None:
    """covered and total are non-negative integers."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        for cell in row["cells"]:
            assert isinstance(cell["covered"], int) and cell["covered"] >= 0
            assert isinstance(cell["total"], int) and cell["total"] >= 0


@pytest.mark.asyncio
async def test_heatmap_opacity_is_float_in_range(
    client: AsyncClient, auth_headers: dict
) -> None:
    """opacity is present on every cell and is a float in [0.0, 1.0]."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        for cell in row["cells"]:
            assert "opacity" in cell
            assert isinstance(cell["opacity"], float)
            assert 0.0 <= cell["opacity"] <= 1.0


@pytest.mark.asyncio
async def test_heatmap_cell_totals_match_attck_v14(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Cell totals match ATT&CK v14 fixed sub-technique counts per tactic column."""
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        for cell in row["cells"]:
            expected = _TACTIC_TOTALS[cell["tactic"]]
            assert cell["total"] == expected, (
                f"{row['technique_id']}/{cell['tactic']}: "
                f"total={cell['total']}, expected={expected}"
            )


@pytest.mark.asyncio
async def test_heatmap_supports_gap_table_aggregation(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Heatmap data can be aggregated per-tactic to produce a valid gap table.

    The frontend buildGapTable() sums covered/total across all rows per tactic and
    sorts ascending by %. This test verifies the data supports that operation.
    """
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    rows = resp.json()

    # Replicate buildGapTable() from CoveragePage.tsx
    gap: dict[str, dict] = {}
    for row in rows:
        for cell in row["cells"]:
            t = cell["tactic"]
            if t not in gap:
                gap[t] = {"covered": 0, "total": 0}
            gap[t]["covered"] += cell["covered"]
            gap[t]["total"] += cell["total"]

    # All 9 tactic columns must be present
    assert set(gap.keys()) == set(_EXPECTED_TACTIC_LABELS)

    # Coverage percentage is valid (0–100) for every tactic
    for tactic, counts in gap.items():
        pct = round(counts["covered"] / counts["total"] * 100) if counts["total"] else 0
        assert 0 <= pct <= 100, f"Gap pct {pct} out of range for tactic {tactic}"


# ===========================================================================
# 3b. GET /api/v1/overview/coverage/heatmap — DB-driven scenarios
# ===========================================================================


def _make_detection(**kwargs):
    """Return a minimal Detection ORM instance for heatmap DB tests."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel

    defaults = dict(
        score=7.0,
        severity="high",
        technique_name="Test Technique",
        name="Test Detection",
        host="host-test",
        tactic_id="TA0002",
        status="active",
        time=datetime.now(timezone.utc),
        description="test",
        user="root",
        process="cmd",
        rule_name="rule-test",
        log_source="syslog",
        event_id="evt-test",
        occurrence_count=1,
        cvss_v3=7.0,
        confidence=80,
        assigned_to=None,
        priority="P2",
    )
    defaults.update(kwargs)
    return DetectionModel(**defaults)


@pytest.mark.asyncio
async def test_heatmap_db_always_four_rows(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """DB-driven heatmap always returns exactly 4 rows regardless of which families have data."""
    db_session.add(_make_detection(technique_id="T1059.001", tactic="Execution"))
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 4


@pytest.mark.asyncio
async def test_heatmap_db_two_sub_techniques_counted_separately(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Two distinct sub-techniques in the same family+tactic → covered == 2."""
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution"),
        _make_detection(technique_id="T1059.003", tactic="Execution"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    exec_cell = next(c for c in t1059["cells"] if c["tactic"] == "EXEC")
    assert exec_cell["covered"] == 2


@pytest.mark.asyncio
async def test_heatmap_db_duplicate_pair_counted_once(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Multiple detections of the same (technique_id, tactic) count as one (DISTINCT)."""
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution", host="host-a"),
        _make_detection(technique_id="T1059.001", tactic="Execution", host="host-b"),
        _make_detection(technique_id="T1059.001", tactic="Execution", host="host-c"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    exec_cell = next(c for c in t1059["cells"] if c["tactic"] == "EXEC")
    assert exec_cell["covered"] == 1  # only 1 distinct sub-technique


@pytest.mark.asyncio
async def test_heatmap_db_multiple_families_covered(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Detections from different families populate their respective rows independently."""
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution"),         # EXEC → T1059
        _make_detection(technique_id="T1003.001", tactic="Credential Access"), # CRED → T1003
        _make_detection(technique_id="T1021.001", tactic="Discovery"),         # DISC → T1021
        _make_detection(technique_id="T1078.002", tactic="Initial Access"),    # INIT → T1078
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    by_family = {r["technique_id"]: r for r in resp.json()}

    def cell(family: str, tactic: str) -> dict:
        return next(c for c in by_family[family]["cells"] if c["tactic"] == tactic)

    assert cell("T1059", "EXEC")["covered"] == 1
    assert cell("T1003", "CRED")["covered"] == 1
    assert cell("T1021", "DISC")["covered"] == 1
    assert cell("T1078", "INIT")["covered"] == 1


@pytest.mark.asyncio
async def test_heatmap_db_unknown_tactic_ignored(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Tactics outside the 9-tactic heatmap scope (e.g. Lateral Movement) are silently ignored."""
    # "Lateral Movement" and "Command and Control" are not in _TACTIC_LABEL_MAP
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Lateral Movement"),
        _make_detection(technique_id="T1059.003", tactic="Command and Control"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    # All 9 cells should have covered=0 because neither tactic maps to a label
    assert all(c["covered"] == 0 for c in t1059["cells"])


@pytest.mark.asyncio
async def test_heatmap_db_non_family_techniques_ignored(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Techniques outside the 4 tracked families contribute zero coverage."""
    # T1110 (Brute Force) is not in {T1059, T1003, T1021, T1078}
    db_session.add(_make_detection(technique_id="T1110.001", tactic="Credential Access"))
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        assert all(c["covered"] == 0 for c in row["cells"]), (
            f"Unexpected coverage in row {row['technique_id']}"
        )


@pytest.mark.asyncio
async def test_heatmap_db_coverage_capped_at_tactic_total(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """covered never exceeds the ATT&CK v14 total for the tactic column (EXEC cap = 14)."""
    # Insert 20 distinct T1059.xxx sub-techniques in Execution — more than EXEC total (14)
    db_session.add_all([
        _make_detection(technique_id=f"T1059.{i:03d}", tactic="Execution")
        for i in range(1, 21)
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    exec_cell = next(c for c in t1059["cells"] if c["tactic"] == "EXEC")
    assert exec_cell["covered"] <= exec_cell["total"] == 14


@pytest.mark.asyncio
async def test_heatmap_db_zero_coverage_rows_included(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Families with no detections still appear in the response with covered=0 everywhere."""
    # Only T1059 has detections — T1003, T1021, T1078 should have zero coverage
    db_session.add(_make_detection(technique_id="T1059.001", tactic="Execution"))
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    rows = {r["technique_id"]: r for r in resp.json()}

    assert set(rows.keys()) == {"T1059", "T1003", "T1021", "T1078"}
    for family in ("T1003", "T1021", "T1078"):
        assert all(c["covered"] == 0 for c in rows[family]["cells"]), (
            f"Row {family} should have zero coverage"
        )


@pytest.mark.asyncio
async def test_heatmap_db_same_sub_technique_in_two_tactics(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """A sub-technique detected under two different tactics contributes to both cells."""
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution"),          # EXEC
        _make_detection(technique_id="T1059.001", tactic="Credential Access"),  # CRED
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    cells = {c["tactic"]: c for c in t1059["cells"]}
    assert cells["EXEC"]["covered"] == 1
    assert cells["CRED"]["covered"] == 1


@pytest.mark.asyncio
async def test_heatmap_db_row_indices_correct(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """row field in the DB-driven response follows the fixed canonical family order."""
    db_session.add(_make_detection(technique_id="T1059.001", tactic="Execution"))
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    idx = {r["technique_id"]: r["row"] for r in resp.json()}
    assert idx == {"T1059": 0, "T1003": 1, "T1021": 2, "T1078": 3}


@pytest.mark.asyncio
async def test_heatmap_db_cell_tactic_order_canonical(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Cell order in DB-driven response matches _EXPECTED_TACTIC_LABELS for every row."""
    db_session.add(_make_detection(technique_id="T1059.001", tactic="Execution"))
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    for row in resp.json():
        assert [c["tactic"] for c in row["cells"]] == _EXPECTED_TACTIC_LABELS


@pytest.mark.asyncio
async def test_heatmap_db_opacity_higher_for_covered_cells(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Covered cells have a strictly higher opacity than completely uncovered cells."""
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution"),
        _make_detection(technique_id="T1059.003", tactic="Execution"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    cells = {c["tactic"]: c for c in t1059["cells"]}
    # EXEC (covered=2) should have a higher opacity than RECON (covered=0)
    assert cells["EXEC"]["opacity"] > cells["RECON"]["opacity"]


@pytest.mark.asyncio
async def test_heatmap_db_cred_coverage_across_sub_techniques(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Multiple T1003 sub-techniques under Credential Access are each counted once."""
    db_session.add_all([
        _make_detection(technique_id="T1003.001", tactic="Credential Access"),
        _make_detection(technique_id="T1003.002", tactic="Credential Access"),
        _make_detection(technique_id="T1003.004", tactic="Credential Access"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1003 = next(r for r in resp.json() if r["technique_id"] == "T1003")
    cred_cell = next(c for c in t1003["cells"] if c["tactic"] == "CRED")
    assert cred_cell["covered"] == 3
    assert cred_cell["total"] == _TACTIC_TOTALS["CRED"]  # 14


@pytest.mark.asyncio
async def test_heatmap_db_gap_table_sortable_by_pct(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Gap table derived from DB heatmap can be sorted by ascending coverage percentage.

    Simulates buildGapTable() from the CoveragePage.tsx frontend component and
    validates the resulting sorted list covers all 9 tactics with valid percentages.
    """
    db_session.add_all([
        _make_detection(technique_id="T1059.001", tactic="Execution"),
        _make_detection(technique_id="T1059.003", tactic="Execution"),
        _make_detection(technique_id="T1003.001", tactic="Credential Access"),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    rows = resp.json()

    # Replicate buildGapTable() from CoveragePage.tsx
    gap: dict[str, dict] = {}
    for row in rows:
        for cell in row["cells"]:
            t = cell["tactic"]
            if t not in gap:
                gap[t] = {"covered": 0, "total": 0}
            gap[t]["covered"] += cell["covered"]
            gap[t]["total"] += cell["total"]

    gap_sorted = sorted(
        [
            {
                "tactic": t,
                "pct": round(v["covered"] / v["total"] * 100) if v["total"] else 0,
            }
            for t, v in gap.items()
        ],
        key=lambda x: x["pct"],
    )

    # All 9 tactics must be present, sorted ascending by pct
    assert len(gap_sorted) == 9
    pcts = [g["pct"] for g in gap_sorted]
    assert pcts == sorted(pcts), "Gap table should be sorted by ascending coverage %"

    # Tactics with actual detections rank above 0 %
    exec_pct = next(g["pct"] for g in gap_sorted if g["tactic"] == "EXEC")
    cred_pct = next(g["pct"] for g in gap_sorted if g["tactic"] == "CRED")
    assert exec_pct > 0, "EXEC coverage should be > 0 after inserting T1059 detections"
    assert cred_pct > 0, "CRED coverage should be > 0 after inserting T1003 detections"


@pytest.mark.asyncio
async def test_heatmap_db_privilege_escalation_tactic_maps_to_priv(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """'Privilege Escalation' tactic correctly maps to the PRIV heatmap column."""
    db_session.add(
        _make_detection(technique_id="T1078.003", tactic="Privilege Escalation")
    )
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1078 = next(r for r in resp.json() if r["technique_id"] == "T1078")
    priv_cell = next(c for c in t1078["cells"] if c["tactic"] == "PRIV")
    assert priv_cell["covered"] == 1


@pytest.mark.asyncio
async def test_heatmap_db_defense_evasion_tactic_maps_to_def_e(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """'Defense Evasion' tactic correctly maps to the DEF-E heatmap column."""
    db_session.add(
        _make_detection(technique_id="T1059.005", tactic="Defense Evasion")
    )
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1059 = next(r for r in resp.json() if r["technique_id"] == "T1059")
    def_e_cell = next(c for c in t1059["cells"] if c["tactic"] == "DEF-E")
    assert def_e_cell["covered"] == 1


@pytest.mark.asyncio
async def test_heatmap_db_persistence_tactic_maps_to_pers(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """'Persistence' tactic correctly maps to the PERS heatmap column."""
    db_session.add(
        _make_detection(technique_id="T1078.004", tactic="Persistence")
    )
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    t1078 = next(r for r in resp.json() if r["technique_id"] == "T1078")
    pers_cell = next(c for c in t1078["cells"] if c["tactic"] == "PERS")
    assert pers_cell["covered"] == 1
