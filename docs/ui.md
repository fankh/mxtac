# User interface

The frontend is a single-page application in `app/frontend/`: React 18, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query and Zustand. Charts use Recharts. The Sigma rule editor uses Monaco.

## Pages

| Page | Path | Content |
|------|------|---------|
| Login | `/login` | Email and password. Asks for a TOTP code when the account has MFA |
| Overview | `/` | KPI cards, detection timeline, top tactics, coverage heatmap, source status, recent detections |
| Detections | `/detections` | Table with filters, sorting and CSV export. A side panel shows one detection. Status changes for one or several detections |
| Incidents | `/incidents` | Incident list with metric cards. Create an incident, change its status, add notes, view the timeline |
| Hunt | `/hunt` | Event search form, result table, charts, event detail sheet, saved queries |
| ATT&CK Coverage | `/coverage` | Coverage statistics, technique matrix, per-source breakdown, trend chart, target dialog |
| Sigma Rules | `/rules` | Rule list. Create, edit, import and test rules |
| Sources | `/sources` | Connector list, connector form, detail sheet, and instructions for the webhook endpoint |
| Settings | `/settings` | Tabs: Profile and security (MFA setup), Users (admin only), Appearance (theme) |

Unknown paths redirect to `/`. All pages except Login require a signed-in user.

The sidebar links to every page. What a user can do on a page depends on the role; the backend enforces it. See [security.md](security.md).

New detections arrive over a WebSocket (`/api/v1/ws/alerts`) and are shown without reloading the page.

## Keyboard shortcuts

| Keys | Action |
|------|--------|
| `g` then `d` | Overview |
| `g` then `e` | Detections |
| `g` then `i` | Incidents |
| `g` then `h` | Hunt |
| `g` then `c` | ATT&CK Coverage |
| `g` then `r` | Sigma Rules |
| `g` then `s` | Sources |
| `/` | Focus the search field |
| `?` | Show the shortcut list |
| `Esc` | Close the shortcut list or the open panel |

Shortcuts are ignored while typing in a field.

## Design tokens

The UI uses a token system in the style of shadcn/ui. Colors are CSS variables, Tailwind maps utility classes to those variables, and components use the utility classes.

| File | Role |
|------|------|
| `src/index.css` | Defines the variables for the light theme under `:root` and for the dark theme under `.dark` |
| `tailwind.config.js` | Maps Tailwind color names (`background`, `foreground`, `card`, `primary`, `secondary`, `muted`, `accent`, `destructive`, `border`) to the variables. Sets `darkMode: 'class'` |
| `src/components/ui/` | Base components built on Radix UI primitives and `class-variance-authority` |

Token groups in `src/index.css`:

| Group | Examples | Use |
|-------|----------|-----|
| Surface and text | `--background`, `--foreground`, `--card`, `--muted`, `--border` | Page, cards, text, borders |
| Action | `--primary`, `--destructive`, `--ring` | Buttons, focus ring |
| Sidebar | `--sidebar-bg`, `--sidebar-active`, `--sidebar-text` | Navigation |
| Charts | `--chart-1` to `--chart-5` | Chart series |
| Severity | `--sev-critical-*`, `--sev-high-*`, `--sev-medium-*`, `--sev-low-*`, `--sev-info-*` | Severity badges, through the classes `sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `sev-info` |
| Status | `--status-green-*`, `--status-purple-*` | Status pills, through the classes `status-green` and `status-purple` |

Base components in `src/components/ui/`: `badge`, `button`, `card`, `dialog`, `dropdown-menu`, `empty-state`, `input`, `label`, `select`, `separator`, `sheet`, `skeleton`, `switch`, `table`, `tabs`, `textarea`.

### Themes

There are two themes, light and dark. The first visit follows the operating system setting. The choice is saved in the browser. The theme is applied by setting the `dark` class and a `data-theme` attribute on the `<html>` element (`src/stores/uiStore.ts`).

### Rules for new UI code

- Use the base components instead of raw `<button>`, `<input>` or `<select>` elements.
- Use token classes (`bg-card`, `text-muted-foreground`, `border-border`) instead of fixed colors, so that both themes work.
- Use the `sev-*` and `status-*` classes for severity and status colors.
