# MxTac - UI/UX Design Guide

> **Version**: 2.0
> **Last Updated**: 2026-02-19
> **Status**: Active — reflects ui-mockup-v2 (overview + detections)

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Design System](#design-system)
3. [Layout & Navigation](#layout--navigation)
4. [Core Screens](#core-screens)
5. [Components](#components)
6. [Interaction Patterns](#interaction-patterns)
7. [Accessibility](#accessibility)
8. [Responsive Design](#responsive-design)
9. [Reference Mockups](#reference-mockups)

---

## Design Philosophy

### Inspiration

The v2 design is informed by Tenable Vulnerability Management's UI language: white/light background, icon-only sidebar, tab navigation, dense data tables, and a slide-out detail panel. The approach is **inspired by**, not a pixel-perfect copy — MxTac keeps its own content structure and security-domain personality.

### Core Principles

| Principle | Description |
|-----------|-------------|
| **Clarity First** | Information should be immediately understandable |
| **Action-Oriented** | Every screen guides users to take action |
| **Context-Rich** | Provide relevant context without overwhelming |
| **Consistent** | Same patterns across all features |
| **Restrained Color** | Color is used functionally, not decoratively |

### Design Goals

| Goal | Implementation |
|------|----------------|
| Reduce alert fatigue | Muted severity palette, smart grouping |
| Speed up investigation | Inline score badges, slide-out detail panel |
| Enable quick decisions | MITRE technique IDs, confidence scores |
| Support collaboration | Assignment chips, status pills |

### User Experience Priorities

```
1. Time to first insight (< 30 seconds)
2. Clicks to investigate alert (< 5 clicks)
3. Cognitive load reduction (progressive disclosure via slide-out panel)
4. Cross-tool context (unified detection view across all integrations)
```

---

## Design System

### Color Palette

The v2 palette is intentionally minimal: **one primary accent** and **one severity accent**. All other visual differentiation is achieved through opacity, weight, and size — not by adding more hues.

#### Primary

| Name | Hex | Usage |
|------|-----|-------|
| **Primary Blue** | `#0066CC` | Accent, active nav, links, buttons, chart fills, heatmap base color |
| **Primary Dark** | `#0055AA` | Hover states, technique ID text |

#### Severity

Severity is the **only place** where additional hues enter the palette. Each severity level uses a muted tinted background with a darker foreground — never bright solid fills.

| Severity | Score range | Badge background | Badge text | Circle fill |
|----------|------------|-----------------|------------|-------------|
| **Critical** | 9.0 – 10.0 | `#FDECEA` | `#CC3333` | `#FDECEA` + `#CC3333` text |
| **High** | 7.0 – 8.9 | `#FEF3E2` | `#CC6600` | `#FEF3E2` + `#CC6600` text |
| **Medium** | 4.0 – 6.9 | `#EBF2FF` | `#0055AA` | `#EBF2FF` + `#0055AA` text |
| **Low** | 0 – 3.9 | `#F4F6F8` | `#A0AABB` | `#F4F6F8` + `#A0AABB` text |

> **Rule**: Never use bright solid severity fills (e.g. `#DC2626` as a background). Always use the muted tinted background variant.

#### Status / Integration

| State | Dot color | Usage |
|-------|-----------|-------|
| **Connected** | `#2E7D32` | Integration online |
| **Warning** | `#CC6600` | Auth error, degraded |
| **Disabled** | `#C8D0DC` | Not configured |

> Status is communicated with a **small circle dot only** — not colored card borders or backgrounds.

#### Alert / Highlight

| Name | Hex | Usage |
|------|-----|-------|
| **Alert Red** | `#CC3333` | Critical counts in KPI cards, escalate button |

#### Neutrals

| Name | Hex | Usage |
|------|-----|-------|
| **Text Primary** | `#1C2D40` | Headlines, table body text |
| **Text Secondary** | `#5A6B82` | Description text, detail panel body |
| **Text Muted** | `#A0AABB` | Column headers, labels, timestamps |
| **Text Faint** | `#C8D0DC` | De-emphasized rows (Low severity) |
| **Surface** | `#FFFFFF` | Cards, panels, header bar, sidebar |
| **Page Background** | `#F4F6F8` | Page-level background |
| **Row Hover / Section** | `#F9FAFB` | Table header fill, group-by bar |
| **Border** | `#E8ECF0` | Card edges, row dividers, panel edges |
| **Border Strong** | `#DDE3EB` | Visible input borders |

#### Selected Row

| State | Background | Left border |
|-------|------------|-------------|
| Selected row | `#F0F6FF` | `3px solid #0066CC` |

### Chart & Data Visualization Rules

| Element | Rule |
|---------|------|
| Bar charts (tactic breakdown) | Uniform `#0066CC` fill, vary width/height for value |
| ATT&CK heatmap | Single-hue `#0066CC` opacity scale: 0.10 (low) → 0.85 (full) |
| Area / line charts | `#0066CC` line 1.5px; `#CC3333` for critical overlay only; area fill 7–25% opacity |
| Sparklines | `#0066CC` line 1.5px, `#0066CC` 7% area fill |
| Progress / coverage bars | `#0066CC` on `#E8ECF0` track |
| Circular gauge (ATT&CK coverage) | `#0066CC` on `#E8ECF0` ring, 5–6px stroke |
| Score circles (detect/CVSSv3) | `#FDECEA` background + `#CC3333` or `#CC6600` number |

### Typography

#### Font Family

```css
/* Primary */
font-family: 'Segoe UI', Inter, -apple-system, sans-serif;

/* Monospace (raw events, log output) */
font-family: 'JetBrains Mono', 'Fira Code', monospace;
```

#### Type Scale

| Name | Size | Weight | Usage |
|------|------|--------|-------|
| **Page title** | 15px | 600 | Header breadcrumb active segment |
| **Card title** | 12–13px | 600 | Panel headings, card labels |
| **Table header** | 9–10px | 500 | Column labels (ALL CAPS, letter-spacing 0.5) |
| **Table body** | 11px | 400 | Row content |
| **Label / caption** | 10px | 400 | KPI sub-labels, timestamps, status |
| **KPI number** | 32px | 700 | Main metric value |
| **Score** | 24–30px | 700 | Score card number |
| **Code / technique ID** | 10–11px | 400 | MITRE technique IDs (link colored) |

### Spacing

```css
/* 4px base grid */
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-5: 20px;
--space-6: 24px;
--space-8: 32px;
```

### Border Radius

```css
--radius-sm: 4px;     /* Buttons, inputs, group-by chips */
--radius-md: 5–6px;   /* Cards */
--radius-pill: 9999px; /* Severity badges, filter chips */
```

### Shadows

```css
/* Card shadow (used on all white cards) */
box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);

/* Slide-out panel shadow */
box-shadow: -2px 0 10px rgba(0, 0, 0, 0.08);
```

---

## Layout & Navigation

### Application Shell

```
┌──────────────────────────────────────────────────────────────────────┐
│ ┌──┐ MxTac / Page Title       Updated HH:MM UTC   ↻  🔔  [KH]      │  ← Top bar (46px, white)
├─┤  ├──────────────────────────────────────────────────────────────────┤
│ │  │ [Tab 1] [Tab 2] [Tab 3]                   [Date Range ▾]        │  ← Tab bar (38px, white)
│ │  ├──────────────────────────────────────────────────────────────────┤
│ │  │ [Filter chips]  [+ Add Filter]  [Export]   N of M results       │  ← Filter bar (40px, white)
│ │  ├──────────────────────────────────────────────────────────────────┤
│ │  │ Group by: [None] [Tactic] [Host]           Sort: Field ↓        │  ← Group-by bar (34px, #FAFBFC)
│ S  │──────────────────────────────────────────────────────────────────│
│ I  │ [Table header row]                                               │  ← Table (fills remaining height)
│ D  │ row…                                                             │
│ E  │ row…                                                             │
│ B  │                                                             ┌────┤
│ A  │                                                             │    │  ← Slide-out detail panel
│ R  │                                                             │    │    (436px wide, right edge)
│    │ [Pagination]                                                │    │
│ 52 │──────────────────────────────────────────────────────────────────│
│ px │ Footer (18px, #F0F2F5)                                          │
└────┴─────────────────────────────────────────────────────────────────┘
```

### Sidebar

| Property | Value |
|----------|-------|
| Width | **52px** (icon-only, no text labels) |
| Background | `#FFFFFF` |
| Right border | `1px solid #E8ECF0` |
| Active item | `#EBF3FF` background + `3px #0066CC` left border |
| Inactive item | Icon at `#A0AABB` |
| Logo | 32×32px `#0066CC` rect, `rx=6`, white "M" |
| Avatar | 20px circle at bottom, `#E8ECF0` background |

Navigation items (top → bottom): Overview ⊞ · Detections ⚡ · ATT&CK ⬡ · Sigma σ · Incidents 🔔 · Intel 🌐 · Assets 🖥 · Reports 📋
Bottom: Help ? · Settings ⚙ · Avatar

### Top Bar

| Property | Value |
|----------|-------|
| Height | 46px |
| Background | `#FFFFFF` |
| Bottom border | `1px solid #E8ECF0` |
| Breadcrumb | Parent segments `#A0AABB`, active segment `#1C2D40` 600 |
| Right area | "Updated HH:MM UTC" label + icon buttons (24×22px `#F4F6F8`) + notification dot `#CC3333` |

### Tab Bar

| Property | Value |
|----------|-------|
| Height | 38px |
| Background | `#FFFFFF` |
| Active tab | `#0066CC` text 600 + `2px #0066CC` bottom underline |
| Inactive tab | `#A0AABB` text |
| Date range picker | Right-aligned, `160×24px`, `#F4F6F8`, `#DDE3EB` border |

### Filter Bar

- Height: 40px, white background
- Filter chips: pill shape (`rx=11`), muted tinted background matching severity or blue; `×` to remove
- "+ Add Filter" button: white with `#DDE3EB` border
- Result count: right-aligned, `#A0AABB`
- Export button: right-aligned, `#0066CC` filled, white text

### Page Footer

Height 18px, `#F0F2F5` background. Left: version + status text. Right: status dot + text.

---

## Core Screens

### Screen 1 — Security Overview

> Reference: `ui-mockup-v2/overview.svg`

**Layout zones (top to bottom):**

```
[Top bar] [Tab bar with date picker]
[6 KPI cards — equal width, white, card-shadow]
[Detection Timeline — 708px wide] [Top ATT&CK Tactics — 536px wide]
[ATT&CK Coverage heatmap — 448px] [Recent Critical Detections — 796px]
[Integration Status row — full width]
[Footer]
```

**KPI Cards (6 total):**

| Card | Primary value | Sub-label style |
|------|--------------|----------------|
| Total Detections | `#1C2D40` 32px 700 | Delta in `#A0AABB` |
| Critical Alerts | `#CC3333` 32px 700 | "N new today" |
| ATT&CK Coverage | Circular gauge `#0066CC` | "X / Y techniques" |
| MTTD | `#1C2D40` 32px 700 | "min" unit label `#A0AABB` |
| Integrations | `#1C2D40` 32px 700 | Thin progress bar `#0066CC` on `#E8ECF0` |
| Sigma Rules | `#1C2D40` 32px 700 | Breakdown in `#A0AABB` |

**Detection Timeline chart:**
- Area chart, two layers: gray total area + red (`#CC3333`) critical overlay
- Y-axis labels `#C8D0DC`, grid lines `#F0F2F5`, baseline `#E8ECF0`
- X-axis date labels `#A0AABB`
- Spike annotation: `#CC3333` dashed vertical line + small red rect label

**Top ATT&CK Tactics table:**
- 6 rows, columns: Tactic name · bar · count · trend
- All bars same `#0066CC` at 0.7 opacity; width is the only variable
- Trend text: `#A0AABB` for neutral, `#CC3333` for notable increases only

**ATT&CK Coverage heatmap:**
- 4 rows × 9 tactic columns
- Single-hue `#0066CC` opacity: `0.10` (1/9) → `0.85` (9/9)
- Text: white when opacity ≥ 0.55, `#0066CC` when 0.28–0.54, `#A0AABB` when ≤ 0.20
- Legend: 4 swatches (Low / Mid / High / Full)
- Summary mini bar chart below: same blue opacity bars

**Recent Critical Detections table:**
- Columns: SEV (circle badge) · TECHNIQUE (link) · DETECTION NAME · HOST · STATUS · TIME
- Score circle: 9px radius, tinted bg, colored score text
- Technique ID: `#0066CC` link style
- Status pills: muted tinted pills only

**Integration Status row:**
- 8 tiles in a single row, each 140×40px, `#F9FAFB` bg, `#E8ECF0` border
- Each tile: small colored dot (left) + name (600) + metric (below, `#A0AABB`)
- Warning tile: `#FFFBF0` bg, `#F0D580` border, dot `#CC6600`, text `#CC6600`
- Disabled tile: 55% opacity, dot `#C8D0DC`

### Screen 2 — Detections

> Reference: `ui-mockup-v2/detections.svg`

**Layout zones:**

```
[Top bar] [Tab bar — Detections active] [Filter bar] [Group-by bar]
[Table header] [Table rows — 11 visible]
[Pagination bar]
+ [Slide-out detail panel — 436px, overlays right side when row selected]
[Footer]
```

**Table columns:**

| Col | Width | Notes |
|-----|-------|-------|
| Checkbox | 26px | 14×14px, `rx=3` |
| Score | 30px | Circle badge, 11px radius |
| SEV | 68px | Pill badge |
| TECHNIQUE | 80px | `#0066CC` monospace |
| DETECTION NAME | ~240px | `#1C2D40`; bold for selected row |
| HOST | 100px | `#1C2D40` |
| TACTIC | 110px | `#A0AABB` |
| STATUS | 88px | Pill badge |
| TIME | 50px | `#A0AABB` |

**Row states:**

| State | Style |
|-------|-------|
| Normal | White bg, `#F4F6F8` row separator |
| Hover | `#F9FAFB` bg |
| Selected | `#F0F6FF` bg + `3px solid #0066CC` left border; checkbox filled blue |
| Low severity | Text `#A0AABB`, secondary text `#C8D0DC` |

**Slide-out Detail Panel:**

- Width: 436px
- Background: `#FFFFFF`
- Left edge: `1px solid #E8ECF0` + drop shadow `-2px 0 10px rgba(0,0,0,0.08)`
- **Header** (52px, `#F9FAFB`): Detection ID + technique badge (`#EBF3FF`) + close `×`
- **Sub-tabs** (32px, white): Details · Timeline · Evidence · Actions — active tab `#0066CC` underline
- **Title block**: 13px 700 title + 10px `#A0AABB` rule/source line
- **Score cards** (4 cards, `#F9FAFB` bg, `#E8ECF0` border):
  - Score: colored number (severity color), label "Critical/High/…"
  - CVSSv3: `#CC6600` number
  - Confidence: `#1C2D40` number
  - Tactic: `#1C2D40` text, `#A0AABB` TA-code
- **Details section**: two-column key-value, key `#A0AABB` 10px, value `#1C2D40` 10px; rule name is `#0066CC` link
- **Description**: `#5A6B82` 10px, 4–5 lines
- **Related techniques**: `#EBF3FF` tags, `#0055AA` text
- **Sparkline**: `#0066CC` 1.5px line, 7% opacity fill, `#E8ECF0` baseline
- **Actions**: Escalate (`#CC3333` filled) · Investigate (`#0066CC` outline) · False Positive (gray outline) · ⋯ (gray)
- **Assigned / Priority**: avatar circle `#E8ECF0`, priority pill `#FDECEA`/`#CC3333`
- **Panel footer** (36px, `#F9FAFB`): ← Prev / Next → navigation

---

## Components

### Score Circle Badge

Used in the detections table and overview table to show a numeric severity score.

```
- Shape: circle, r=11px
- Fill: muted tinted severity background
- Text: 9px, 700, severity text color
- Critical (≥9): #FDECEA fill, #CC3333 text
- High (7–8.9): #FEF3E2 fill, #CC6600 text
- Medium (4–6.9): #EBF2FF fill, #0055AA text
- Low (<4): #F4F6F8 fill, #A0AABB text
```

### Severity Pill Badge

Used in table rows and the slide-out panel.

```
- Shape: rx=8 (rounded pill)
- Padding: 8px horizontal, 16px height
- Font: 9–10px, 500

Critical: bg #FDECEA, text #CC3333, label "Critical"
High:     bg #FEF3E2, text #CC6600, label "High"
Medium:   bg #EBF2FF, text #0055AA, label "Medium"
Low:      bg #F4F6F8, text #A0AABB, label "Low"
```

### Status Pill

```
Active:       bg #FDECEA, text #CC3333
Investigating: bg #FEF3E2, text #CC6600
Resolved:     bg #EBF5EB, text #2E7D32
```

### Filter Chip

```
- Shape: rx=11 (full pill), 22px height
- Has ×  to dismiss

Severity chip: bg #FDECEA, border #F5C6C6, text #CC3333
Generic chip:  bg #EBF3FF, border #C0D6F7, text #0055AA
```

### Group-By Button

```
Active:   #0066CC fill, white text, rx=4
Inactive: white fill, #DDE3EB border, #5A6B82 text, rx=4
```

### KPI Card

```
- White bg, rx=6, card-shadow
- Label: 10px, 500, #A0AABB, letter-spacing 0.5, ALL CAPS
- Value: 32px, 700, #1C2D40 (or #CC3333 for critical count)
- Sub-label: 11px, #A0AABB
```

### Data Table

| Feature | Implementation |
|---------|----------------|
| Sortable columns | Click header, active column shows ↓ ↑ |
| Row selection | Checkbox; selected row gets blue left border + `#F0F6FF` bg |
| Expandable detail | Click row → slide-out panel appears on right |
| Column headers | `#F4F6F8` fill, 9px UPPERCASE labels, `#A0AABB` |
| Dividers | `#F4F6F8` between rows; `#E8ECF0` after header |
| Pagination | Page buttons; active `#0066CC`, inactive white + `#DDE3EB` border |

### Slide-Out Detail Panel

- Triggered by row selection (not a modal — does not block the table)
- Animates in from the right: `transform: translateX(100%)` → `translateX(0)`, 250ms ease-in-out
- Table width adjusts: panel overlaps the rightmost table columns
- Dismissed by clicking `×`, pressing `Esc`, or clicking another section
- Sub-tab navigation for progressive disclosure: Details → Timeline → Evidence → Actions

### Chart Components

| Chart | Config |
|-------|--------|
| Area timeline | Two polygon layers (gray total + red critical), polyline strokes |
| Horizontal bar | `#0066CC` at 0.7 opacity on `#E8ECF0` track, fixed height 8px, rx=4 |
| ATT&CK heatmap | Rect grid cells, single-hue blue opacity, rounded corners rx=3 |
| Circular gauge | SVG circle with `stroke-dasharray`, `stroke-linecap=round`, 5–6px |
| Sparkline | Thin polygon fill + polyline, inline in panel |
| Coverage bar | `#0066CC` on `#E8ECF0` track, 5px height, rx=2 |

---

## Interaction Patterns

### Quick Actions

| Context | Actions |
|---------|---------|
| Alert row (hover) | Row highlights `#F9FAFB`; click opens slide-out panel |
| Slide-out panel | Escalate · Investigate · False Positive · ⋯ menu |
| Filter chip | Click `×` to remove; "Clear all" to reset |
| Technique ID | Click → opens ATT&CK Map tab with technique highlighted |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `/` | Focus search |
| `j` / `k` | Navigate table rows up/down |
| `Enter` | Open slide-out panel for selected row |
| `Esc` | Close slide-out panel |
| `a` | Acknowledge / mark resolved |
| `?` | Show shortcuts overlay |

### Progressive Disclosure

| Level | Surface | Content |
|-------|---------|---------|
| 1 — Summary | Table row | Score · Severity · Technique ID · Name · Host · Status · Time |
| 2 — Detail | Slide-out: Details tab | Score cards · key-value fields · description · related techniques |
| 3 — Evidence | Slide-out: Evidence tab | Raw event JSON, log lines |
| 4 — Timeline | Slide-out: Timeline tab | Chronological event chain on host |
| 5 — Actions | Slide-out: Actions tab | Response playbooks, assignment |

---

## Accessibility

### WCAG 2.1 AA Compliance

| Requirement | Implementation |
|-------------|----------------|
| Color contrast | 4.5:1 minimum; blue `#0066CC` on white passes AA |
| Keyboard navigation | Full keyboard support; table rows navigable with j/k |
| Screen reader | ARIA labels on badges, ARIA live region for count updates |
| Focus indicators | `2px solid #0066CC`, `outline-offset: 2px` |
| Non-color indicators | Severity shown by score number + label text, not color alone |

### Color Rule Enforcement

- **Never** convey severity by color alone — always pair with a number (score) or label text
- All severity circles show a numeric score inside; all pills show a text label
- Integration status dots always accompanied by status text below

### Screen Reader Examples

```html
<!-- Score circle -->
<span role="img" aria-label="Detection score 9.0, Critical">9.0</span>

<!-- Severity pill -->
<span class="badge" role="status" aria-label="Critical severity">Critical</span>

<!-- Alert count live region -->
<span aria-live="polite" aria-atomic="true">47 critical detections</span>
```

---

## Responsive Design

MxTac is designed for **1280px+ desktop** (security operations center context). Tablet and mobile are secondary use cases.

### Breakpoints

| Name | Width | Behavior |
|------|-------|----------|
| `xl` | 1280px | Primary target — all panels visible |
| `lg` | 1024px | Slide-out panel overlaps more of table |
| `md` | 768px | Sidebar collapses to hamburger drawer |
| `sm` | 640px | Table switches to card list view |

### Sidebar Behavior

| Breakpoint | Sidebar |
|------------|---------|
| ≥ 1024px | Fixed 52px icon-only sidebar |
| < 1024px | Hidden; hamburger icon in top bar opens drawer overlay |

---

## Reference Mockups

Current design artifacts are in `mitre-attack/mxtac/ui-mockup-v2/`:

| File | Description |
|------|-------------|
| `overview.svg` / `overview.png` | Security Overview dashboard — KPI cards, timeline chart, ATT&CK heatmap, detections table, integration status row |
| `detections.svg` / `detections.png` | Detections table view — filter chips, group-by bar, dense table, slide-out detail panel |

The original dark-theme mockup is at `UI-MOCKUP.svg` / `UI-MOCKUP.png` (v1, superseded).

Reference screenshots from real products are in `dashboard-examples/real-screenshots/`. The primary design reference is `06-tenable-real.png` (Tenable Vulnerability Management Explore view).

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| **2.0** | 2026-02-19 | Full v2 redesign: light theme, icon-only sidebar, Tenable-inspired layout; reduced palette to 2 accent colors; added slide-out panel pattern; updated all screen specs and component definitions |
| 1.0 | 2026-01-12 | Initial dark-theme design guide |

---

*Document maintained by MxTac Project*
