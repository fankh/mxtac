# MxTac - UI/UX Design Guide

> **Version**: 1.0  
> **Last Updated**: 2026-01-12  
> **Status**: Draft

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

---

## Design Philosophy

### Core Principles

| Principle | Description |
|-----------|-------------|
| **Clarity First** | Information should be immediately understandable |
| **Action-Oriented** | Every screen should guide users to take action |
| **Context-Rich** | Provide relevant context without overwhelming |
| **Consistent** | Same patterns across all features |
| **Performance** | Fast load times, responsive interactions |

### Design Goals

| Goal | Implementation |
|------|----------------|
| Reduce alert fatigue | Smart grouping, severity indicators |
| Speed up investigation | One-click pivots, entity timelines |
| Enable quick decisions | Risk scores, recommendations |
| Support collaboration | Shared views, assignment workflows |

### User Experience Priorities

```
1. Time to first insight (< 30 seconds)
2. Clicks to investigate alert (< 5 clicks)
3. Cognitive load reduction (progressive disclosure)
4. Cross-tool context (unified view)
```

---

## Design System

### Color Palette

#### Primary Colors

| Name | Hex | Usage |
|------|-----|-------|
| **Primary Blue** | `#1E3A5F` | Primary actions, headers |
| **Primary Light** | `#2E5A8F` | Hover states |
| **Primary Dark** | `#0E2A4F` | Active states |

#### Severity Colors

| Severity | Hex | Background | Usage |
|----------|-----|------------|-------|
| **Critical** | `#DC2626` | `#FEF2F2` | Critical alerts |
| **High** | `#EA580C` | `#FFF7ED` | High severity |
| **Medium** | `#CA8A04` | `#FEFCE8` | Medium severity |
| **Low** | `#16A34A` | `#F0FDF4` | Low severity |
| **Info** | `#2563EB` | `#EFF6FF` | Informational |

#### Status Colors

| Status | Hex | Usage |
|--------|-----|-------|
| **Success** | `#16A34A` | Success states |
| **Warning** | `#CA8A04` | Warning states |
| **Error** | `#DC2626` | Error states |
| **Info** | `#2563EB` | Info states |

#### Neutral Colors

| Name | Hex | Usage |
|------|-----|-------|
| **Gray 900** | `#111827` | Primary text |
| **Gray 700** | `#374151` | Secondary text |
| **Gray 500** | `#6B7280` | Tertiary text |
| **Gray 300** | `#D1D5DB` | Borders |
| **Gray 100** | `#F3F4F6` | Backgrounds |
| **White** | `#FFFFFF` | Cards, panels |

### Typography

#### Font Family

```css
/* Primary */
font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;

/* Monospace (code, logs) */
font-family: 'JetBrains Mono', 'Fira Code', monospace;
```

#### Type Scale

| Name | Size | Weight | Line Height | Usage |
|------|------|--------|-------------|-------|
| **Display** | 36px | 700 | 1.2 | Page titles |
| **Heading 1** | 24px | 600 | 1.3 | Section titles |
| **Heading 2** | 20px | 600 | 1.4 | Subsections |
| **Heading 3** | 16px | 600 | 1.4 | Card titles |
| **Body** | 14px | 400 | 1.5 | Body text |
| **Body Small** | 13px | 400 | 1.5 | Secondary text |
| **Caption** | 12px | 400 | 1.4 | Labels, captions |
| **Code** | 13px | 400 | 1.5 | Code, logs |

### Spacing

```css
/* Spacing scale (4px base) */
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-5: 20px;
--space-6: 24px;
--space-8: 32px;
--space-10: 40px;
--space-12: 48px;
--space-16: 64px;
```

### Border Radius

```css
--radius-sm: 4px;   /* Buttons, inputs */
--radius-md: 6px;   /* Cards */
--radius-lg: 8px;   /* Modals */
--radius-xl: 12px;  /* Large cards */
--radius-full: 9999px; /* Pills, avatars */
```

### Shadows

```css
--shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
--shadow-md: 0 4px 6px rgba(0, 0, 0, 0.07);
--shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
--shadow-xl: 0 20px 25px rgba(0, 0, 0, 0.1);
```

---

## Layout & Navigation

### Application Shell

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ┌──────┐  MxTac              Search...              [?] [🔔] [👤]     │
│  │ Logo │                                                              │
├──┴──────┴───────────────────────────────────────────────────────────────┤
│ ┌────────────┐ ┌───────────────────────────────────────────────────────┐│
│ │            │ │                                                       ││
│ │  SIDEBAR   │ │                    MAIN CONTENT                       ││
│ │            │ │                                                       ││
│ │ Dashboard  │ │                                                       ││
│ │ Alerts     │ │                                                       ││
│ │ Hunting    │ │                                                       ││
│ │ Rules      │ │                                                       ││
│ │ Coverage   │ │                                                       ││
│ │ Connectors │ │                                                       ││
│ │ Reports    │ │                                                       ││
│ │            │ │                                                       ││
│ │ ────────── │ │                                                       ││
│ │ Settings   │ │                                                       ││
│ │ Help       │ │                                                       ││
│ │            │ │                                                       ││
│ └────────────┘ └───────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### Header Components

| Component | Purpose |
|-----------|---------|
| **Logo** | Brand, home navigation |
| **Global Search** | Cross-feature search |
| **Help** | Documentation, support |
| **Notifications** | Real-time alerts |
| **User Menu** | Profile, logout |

### Sidebar Navigation

| Section | Items |
|---------|-------|
| **Core** | Dashboard, Alerts, Hunting |
| **Management** | Rules, Coverage, Connectors |
| **Analytics** | Reports |
| **System** | Settings, Help |

### Navigation States

```
Default:    Gray text, no background
Hover:      Slightly darker background
Active:     Primary color background, white text
Collapsed:  Icons only with tooltips
```

---

## Core Screens

### Dashboard

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Dashboard                                        Last updated: 10:30   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │   Critical   │ │     High     │ │    Medium    │ │   Coverage   │   │
│  │      12      │ │      45      │ │     128      │ │     72%      │   │
│  │   +3 today   │ │   -5 today   │ │   +12 today  │ │   +2% week   │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────┐ ┌─────────────────────────────┐   │
│  │      Alert Trend (7 days)       │ │    ATT&CK Coverage Map     │   │
│  │   ┌───────────────────────┐     │ │  ┌────┬────┬────┬────┐     │   │
│  │   │    📈 Chart           │     │ │  │ IA │ EX │ PE │ PR │     │   │
│  │   │                       │     │ │  │ 85%│ 90%│ 80%│ 75%│     │   │
│  │   └───────────────────────┘     │ │  └────┴────┴────┴────┘     │   │
│  └─────────────────────────────────┘ └─────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────┐ ┌─────────────────────────────┐   │
│  │     Recent Critical Alerts      │ │   Top Techniques (24h)     │   │
│  │  ┌───────────────────────────┐  │ │  1. T1059 - Execution      │   │
│  │  │ ● Mimikatz detected       │  │ │  2. T1003 - Cred Access    │   │
│  │  │ ● C2 beacon (APT29)       │  │ │  3. T1071 - C2             │   │
│  │  │ ● Ransomware behavior     │  │ │  4. T1021 - Lateral        │   │
│  │  └───────────────────────────┘  │ │  5. T1055 - Injection      │   │
│  └─────────────────────────────────┘ └─────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Alerts List

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Alerts                                                      [+ Filter] │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ [All] [Critical 12] [High 45] [Medium 128] [Low 89]  │ New ▼ │   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ □ │ SEV │ TIME     │ TITLE                    │ SOURCE │ ATTCK  │   │
│  ├───┼─────┼──────────┼──────────────────────────┼────────┼────────┤   │
│  │ □ │ ●●● │ 10:30:22 │ Mimikatz detected        │ Wazuh  │ T1003  │   │
│  │   │ CRI │          │ Host: ws-01, User: admin │        │        │   │
│  ├───┼─────┼──────────┼──────────────────────────┼────────┼────────┤   │
│  │ □ │ ●●  │ 10:28:15 │ C2 beacon detected       │ Zeek   │ T1071  │   │
│  │   │ HIG │          │ Dst: 45.33.x.x:443       │        │        │   │
│  ├───┼─────┼──────────┼──────────────────────────┼────────┼────────┤   │
│  │ □ │ ●●  │ 10:25:00 │ Lateral movement SSH     │ Wazuh  │ T1021  │   │
│  │   │ HIG │          │ Src: 192.168.1.50        │        │        │   │
│  └───┴─────┴──────────┴──────────────────────────┴────────┴────────┘   │
│                                                                         │
│  ◀ Prev │ Page 1 of 24 │ Next ▶                    Showing 1-50 of 274 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Alert Detail

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Alerts                                   [Acknowledge] [Actions ▼]   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ ●●● CRITICAL                                         Risk: 95/100│   │
│  │                                                                   │   │
│  │ Mimikatz Detection - Credential Dumping                          │   │
│  │                                                                   │   │
│  │ Detected at: 2026-01-12 10:30:22 │ Source: Wazuh │ Status: New   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─ ATT&CK ───────────────────────────────────────────────────────┐    │
│  │  Technique: T1003.001 - LSASS Memory                           │    │
│  │  Tactic: Credential Access                                      │    │
│  │  [View in ATT&CK Navigator]                                     │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─ Entities ─────────────────────────────────────────────────────┐    │
│  │  Host: workstation-01  [View Timeline]                          │    │
│  │  User: admin           [View Activity]                          │    │
│  │  IP: 192.168.1.50      [View Connections]                       │    │
│  │  Process: powershell.exe                                        │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─ Raw Event ────────────────────────────────────────────────────┐    │
│  │ {                                                               │    │
│  │   "class_uid": 1007,                                            │    │
│  │   "process": {                                                  │    │
│  │     "cmd_line": "powershell -ep bypass -c \"IEX...\"",         │    │
│  │     "file": {"path": "C:\\Windows\\...\\powershell.exe"}       │    │
│  │   }                                                             │    │
│  │ }                                                               │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─ Related Alerts (3) ───────────────────────────────────────────┐    │
│  │  • 10:28 - C2 beacon detected (T1071)                          │    │
│  │  • 10:25 - Lateral movement SSH (T1021)                        │    │
│  │  • 10:20 - Suspicious script execution (T1059)                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### ATT&CK Coverage

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ATT&CK Coverage                               [Export ▼] [Settings]    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Overall Coverage: 72%  ████████████████████░░░░░░░░                    │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    ATT&CK Navigator Heatmap                       │   │
│  │                                                                   │   │
│  │    Recon │ Res. │ Init │ Exec │ Pers │ Priv │ Def. │ Cred │...   │   │
│  │  ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐       │   │
│  │  │  20% │  10% │  85% │  90% │  80% │  75% │  65% │  70% │       │   │
│  │  │ ░░░░ │ ░░░░ │ ████ │ ████ │ ████ │ ███░ │ ██░░ │ ███░ │       │   │
│  │  └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘       │   │
│  │                                                                   │   │
│  │  Legend: ░ 0-25% │ ▒ 26-50% │ ▓ 51-75% │ █ 76-100%              │   │
│  │                                                                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─ Coverage by Source ──────────────────────────────────────────┐     │
│  │  Wazuh (EDR)    ████████████████░░░░░░░░░░░░░  45%            │     │
│  │  Zeek (NDR)     █████░░░░░░░░░░░░░░░░░░░░░░░░  15%            │     │
│  │  Suricata (IDS) ████░░░░░░░░░░░░░░░░░░░░░░░░░  12%            │     │
│  │  Prowler (Cloud)███░░░░░░░░░░░░░░░░░░░░░░░░░░  10%            │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
│  ┌─ Top Coverage Gaps ───────────────────────────────────────────┐     │
│  │  1. T1055 Process Injection - No detection (High priority)    │     │
│  │  2. T1027 Obfuscated Files - Partial (Medium priority)        │     │
│  │  3. T1562 Impair Defenses - No detection (High priority)      │     │
│  │  [View All Gaps]                                               │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Hunting / Search

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Hunting                                        [Saved Queries] [Help]  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 🔍 process.cmd_line:*mimikatz* OR process.cmd_line:*sekurlsa*   │   │
│  │                                                                   │   │
│  │ Time: [Last 24 hours ▼]  Source: [All ▼]  [Search]              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Results: 23 events (0.045s)                                            │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ TIME         │ CLASS           │ HOST         │ SUMMARY          │   │
│  ├──────────────┼─────────────────┼──────────────┼──────────────────┤   │
│  │ 10:29:55     │ Process Activity│ workstation-01│ powershell.exe  │   │
│  │              │                 │              │ sekurlsa::logon  │   │
│  ├──────────────┼─────────────────┼──────────────┼──────────────────┤   │
│  │ 10:28:30     │ Process Activity│ workstation-01│ mimikatz.exe    │   │
│  │              │                 │              │ privilege::debug │   │
│  └──────────────┴─────────────────┴──────────────┴──────────────────┘   │
│                                                                         │
│  ┌─ Quick Filters ───────────────────────────────────────────────┐     │
│  │ Host: [workstation-01 ×] User: [admin ×] Class: [Process ×]   │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### Severity Badge

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  Critical:  [●●● CRITICAL]  (Red background, white text)               │
│  High:      [●●  HIGH]      (Orange background, white text)            │
│  Medium:    [●   MEDIUM]    (Yellow background, dark text)             │
│  Low:       [    LOW]       (Green background, white text)             │
│  Info:      [ℹ   INFO]      (Blue background, white text)              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Alert Card

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ●●● CRITICAL                                              Risk: 95    │
│                                                                         │
│ Mimikatz Detection - Credential Dumping                                 │
│                                                                         │
│ Host: workstation-01 │ User: admin │ T1003.001                         │
│                                                                         │
│ 10:30:22 │ Wazuh │ [View Details]                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Entity Pill

```
┌────────────────────────────────────────────────────┐
│  Host: [🖥️ workstation-01 ×]                       │
│  User: [👤 admin ×]                                │
│  IP:   [🌐 192.168.1.50 ×]                        │
│  Tech: [🎯 T1003.001 ×]                           │
└────────────────────────────────────────────────────┘
```

### Data Table

| Feature | Implementation |
|---------|----------------|
| Sortable columns | Click header to sort |
| Resizable columns | Drag column border |
| Row selection | Checkbox for bulk actions |
| Expandable rows | Click to show details |
| Column visibility | Hide/show columns |
| Export | CSV, JSON export |

### Chart Types

| Chart | Use Case |
|-------|----------|
| Line chart | Trends over time |
| Bar chart | Comparisons |
| Pie/Donut | Proportions |
| Heatmap | ATT&CK coverage |
| Sparkline | Inline trends |

### Modal Dialog

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────┐     │
│  │  Confirm Action                                            ✕  │     │
│  ├───────────────────────────────────────────────────────────────┤     │
│  │                                                               │     │
│  │  Are you sure you want to isolate host workstation-01?       │     │
│  │                                                               │     │
│  │  This action will:                                            │     │
│  │  • Block all network traffic                                  │     │
│  │  • Require admin approval to reconnect                        │     │
│  │                                                               │     │
│  │                                    [Cancel]  [Isolate Host]   │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Interaction Patterns

### Quick Actions

| Context | Actions |
|---------|---------|
| Alert row | View, Acknowledge, Assign |
| Entity pill | View timeline, Search, Block |
| Event row | View details, Pivot, Add to investigation |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `/` | Focus search |
| `j` / `k` | Navigate list up/down |
| `Enter` | Open selected item |
| `a` | Acknowledge alert |
| `Esc` | Close modal/panel |
| `?` | Show shortcuts |

### Drag and Drop

| Feature | Behavior |
|---------|----------|
| Column reorder | Drag column headers |
| Dashboard widgets | Rearrange widgets |
| Query builder | Drag fields to build queries |

### Progressive Disclosure

| Level | Content |
|-------|---------|
| Summary | Title, severity, time |
| Preview | + Key entities, ATT&CK |
| Full | + Raw event, related alerts |

### Loading States

```
┌──────────────────────────────────────────────────┐
│  Loading data...                                 │
│  ────────────────────────────▓░░░░░░░░░░░░       │
│                                                  │
│  [Cancel]                                        │
└──────────────────────────────────────────────────┘
```

### Empty States

```
┌──────────────────────────────────────────────────┐
│                                                  │
│           🔍                                     │
│                                                  │
│     No alerts match your filters                │
│                                                  │
│     Try adjusting your filters or               │
│     expanding the time range.                   │
│                                                  │
│     [Clear Filters]                             │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## Accessibility

### WCAG 2.1 AA Compliance

| Requirement | Implementation |
|-------------|----------------|
| Color contrast | 4.5:1 minimum for text |
| Keyboard navigation | Full keyboard support |
| Screen reader | ARIA labels, landmarks |
| Focus indicators | Visible focus rings |
| Error messages | Associated with inputs |

### Color Accessibility

- Never use color alone to convey information
- Include icons or text with color indicators
- Test with color blindness simulators

### Keyboard Focus

```css
/* Focus styles */
:focus-visible {
  outline: 2px solid #1E3A5F;
  outline-offset: 2px;
}
```

### Screen Reader Support

```html
<!-- Severity badge -->
<span class="badge badge-critical" role="status" aria-label="Critical severity">
  CRITICAL
</span>

<!-- Alert count -->
<span aria-live="polite" aria-atomic="true">
  12 critical alerts
</span>
```

---

## Responsive Design

### Breakpoints

| Name | Width | Usage |
|------|-------|-------|
| `sm` | 640px | Mobile |
| `md` | 768px | Tablet |
| `lg` | 1024px | Small desktop |
| `xl` | 1280px | Desktop |
| `2xl` | 1536px | Large desktop |

### Mobile Adaptations

| Component | Desktop | Mobile |
|-----------|---------|--------|
| Sidebar | Fixed | Drawer (hamburger) |
| Data table | Full | Card view |
| Filters | Inline | Bottom sheet |
| Actions | Button row | Action menu |

### Responsive Layout

```
Desktop (>1024px):
┌────────────┬─────────────────────────────────────┐
│  Sidebar   │          Main Content               │
│            │                                     │
└────────────┴─────────────────────────────────────┘

Tablet (768-1024px):
┌────────────────────────────────────────────────┐
│  [☰]  Header                                   │
├────────────────────────────────────────────────┤
│              Main Content                      │
│                                                │
└────────────────────────────────────────────────┘

Mobile (<768px):
┌──────────────────────────────────┐
│  [☰]  MxTac                      │
├──────────────────────────────────┤
│         Main Content             │
│                                  │
├──────────────────────────────────┤
│  [Home] [Alerts] [Hunt] [More]  │
└──────────────────────────────────┘
```

---

## Appendix

### A. Icon Library

Using **Lucide Icons** (MIT License)

| Category | Icons |
|----------|-------|
| Navigation | Home, AlertTriangle, Search, Settings |
| Actions | Play, Pause, Download, Upload, Edit, Trash |
| Status | Check, X, AlertCircle, Info |
| Entities | Monitor, User, Globe, Shield |

### B. Animation Guidelines

| Type | Duration | Easing |
|------|----------|--------|
| Micro (hover) | 100-150ms | ease-out |
| Small (collapse) | 200-250ms | ease-in-out |
| Medium (modal) | 250-300ms | ease-in-out |
| Large (page) | 300-400ms | ease-out |

### C. z-index Scale

| Layer | z-index | Usage |
|-------|---------|-------|
| Base | 0 | Normal content |
| Dropdown | 10 | Dropdowns, popovers |
| Sticky | 20 | Sticky headers |
| Sidebar | 30 | Navigation sidebar |
| Modal backdrop | 40 | Modal overlay |
| Modal | 50 | Modal dialog |
| Toast | 60 | Notifications |

---

*Document maintained by MxTac Project*
