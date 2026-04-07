import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { overviewApi, coverageApi, eventsApi } from '../../../lib/api'
import type { HeatRow, CoverageTrend } from '../../../types/api'
import { TopBar } from '../../layout/TopBar'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'

// MITRE ATT&CK Enterprise v15 — real techniques per tactic
const TACTICS: { id: string; name: string; techniques: { id: string; name: string }[] }[] = [
  { id: 'TA0043', name: 'Reconnaissance', techniques: [
    { id: 'T1595', name: 'Active Scanning' },
    { id: 'T1592', name: 'Gather Victim Host Info' },
    { id: 'T1589', name: 'Gather Victim Identity' },
    { id: 'T1590', name: 'Gather Victim Network Info' },
    { id: 'T1591', name: 'Gather Victim Org Info' },
    { id: 'T1598', name: 'Phishing for Information' },
    { id: 'T1597', name: 'Search Closed Sources' },
    { id: 'T1596', name: 'Search Open Tech DBs' },
    { id: 'T1593', name: 'Search Open Websites' },
    { id: 'T1594', name: 'Search Victim Infra' },
  ]},
  { id: 'TA0042', name: 'Resource Dev', techniques: [
    { id: 'T1583', name: 'Acquire Infrastructure' },
    { id: 'T1586', name: 'Compromise Accounts' },
    { id: 'T1584', name: 'Compromise Infrastructure' },
    { id: 'T1587', name: 'Develop Capabilities' },
    { id: 'T1585', name: 'Establish Accounts' },
    { id: 'T1588', name: 'Obtain Capabilities' },
    { id: 'T1608', name: 'Stage Capabilities' },
  ]},
  { id: 'TA0001', name: 'Initial Access', techniques: [
    { id: 'T1189', name: 'Drive-by Compromise' },
    { id: 'T1190', name: 'Exploit Public App' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1200', name: 'Hardware Additions' },
    { id: 'T1566', name: 'Phishing' },
    { id: 'T1091', name: 'Replication via Media' },
    { id: 'T1195', name: 'Supply Chain Compromise' },
    { id: 'T1199', name: 'Trusted Relationship' },
    { id: 'T1078', name: 'Valid Accounts' },
  ]},
  { id: 'TA0002', name: 'Execution', techniques: [
    { id: 'T1059', name: 'Command & Scripting' },
    { id: 'T1609', name: 'Container Admin Cmd' },
    { id: 'T1610', name: 'Deploy Container' },
    { id: 'T1203', name: 'Exploitation for Client' },
    { id: 'T1559', name: 'Inter-Process Comm' },
    { id: 'T1106', name: 'Native API' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1129', name: 'Shared Modules' },
    { id: 'T1072', name: 'Software Deploy Tools' },
    { id: 'T1569', name: 'System Services' },
    { id: 'T1204', name: 'User Execution' },
    { id: 'T1047', name: 'WMI' },
  ]},
  { id: 'TA0003', name: 'Persistence', techniques: [
    { id: 'T1098', name: 'Account Manipulation' },
    { id: 'T1197', name: 'BITS Jobs' },
    { id: 'T1547', name: 'Boot/Logon Autostart' },
    { id: 'T1037', name: 'Boot/Logon Init Scripts' },
    { id: 'T1176', name: 'Browser Extensions' },
    { id: 'T1554', name: 'Compromise Client SW' },
    { id: 'T1136', name: 'Create Account' },
    { id: 'T1543', name: 'Create/Modify Sys Proc' },
    { id: 'T1546', name: 'Event Triggered Exec' },
    { id: 'T1133', name: 'External Remote Services' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
    { id: 'T1525', name: 'Implant Container Image' },
    { id: 'T1556', name: 'Modify Auth Process' },
    { id: 'T1137', name: 'Office App Startup' },
    { id: 'T1542', name: 'Pre-OS Boot' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1505', name: 'Server Software Comp' },
    { id: 'T1078', name: 'Valid Accounts' },
  ]},
  { id: 'TA0004', name: 'Privilege Esc', techniques: [
    { id: 'T1548', name: 'Abuse Elevation Ctrl' },
    { id: 'T1134', name: 'Access Token Manip' },
    { id: 'T1547', name: 'Boot/Logon Autostart' },
    { id: 'T1543', name: 'Create/Modify Sys Proc' },
    { id: 'T1484', name: 'Domain Policy Mod' },
    { id: 'T1611', name: 'Escape to Host' },
    { id: 'T1546', name: 'Event Triggered Exec' },
    { id: 'T1068', name: 'Exploitation for Priv' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
    { id: 'T1078', name: 'Valid Accounts' },
  ]},
  { id: 'TA0005', name: 'Defense Evasion', techniques: [
    { id: 'T1548', name: 'Abuse Elevation Ctrl' },
    { id: 'T1134', name: 'Access Token Manip' },
    { id: 'T1197', name: 'BITS Jobs' },
    { id: 'T1140', name: 'Deobfuscate/Decode' },
    { id: 'T1006', name: 'Direct Volume Access' },
    { id: 'T1484', name: 'Domain Policy Mod' },
    { id: 'T1480', name: 'Execution Guardrails' },
    { id: 'T1211', name: 'Exploitation for Def' },
    { id: 'T1222', name: 'File/Dir Permissions' },
    { id: 'T1564', name: 'Hide Artifacts' },
    { id: 'T1574', name: 'Hijack Execution Flow' },
    { id: 'T1562', name: 'Impair Defenses' },
    { id: 'T1070', name: 'Indicator Removal' },
    { id: 'T1202', name: 'Indirect Command Exec' },
    { id: 'T1036', name: 'Masquerading' },
    { id: 'T1112', name: 'Modify Registry' },
    { id: 'T1027', name: 'Obfuscated Files' },
    { id: 'T1055', name: 'Process Injection' },
    { id: 'T1207', name: 'Rogue Domain Ctrl' },
    { id: 'T1014', name: 'Rootkit' },
    { id: 'T1218', name: 'System Binary Proxy' },
    { id: 'T1216', name: 'System Script Proxy' },
    { id: 'T1221', name: 'Template Injection' },
    { id: 'T1205', name: 'Traffic Signaling' },
    { id: 'T1078', name: 'Valid Accounts' },
    { id: 'T1497', name: 'Virtualization/Sandbox' },
    { id: 'T1600', name: 'Weaken Encryption' },
  ]},
  { id: 'TA0006', name: 'Credential Access', techniques: [
    { id: 'T1557', name: 'Adversary-in-the-Middle' },
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1555', name: 'Credentials from Stores' },
    { id: 'T1212', name: 'Exploitation for Cred' },
    { id: 'T1187', name: 'Forced Authentication' },
    { id: 'T1606', name: 'Forge Web Credentials' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1556', name: 'Modify Auth Process' },
    { id: 'T1111', name: 'Multi-Factor Intercept' },
    { id: 'T1621', name: 'MFA Request Gen' },
    { id: 'T1040', name: 'Network Sniffing' },
    { id: 'T1003', name: 'OS Credential Dumping' },
    { id: 'T1528', name: 'Steal App Access Token' },
    { id: 'T1558', name: 'Steal/Forge Kerberos' },
    { id: 'T1539', name: 'Steal Web Session' },
    { id: 'T1552', name: 'Unsecured Credentials' },
  ]},
  { id: 'TA0007', name: 'Discovery', techniques: [
    { id: 'T1087', name: 'Account Discovery' },
    { id: 'T1010', name: 'Application Window' },
    { id: 'T1217', name: 'Browser Information' },
    { id: 'T1580', name: 'Cloud Infra Discovery' },
    { id: 'T1538', name: 'Cloud Service Dashboard' },
    { id: 'T1526', name: 'Cloud Service Discovery' },
    { id: 'T1613', name: 'Container Discovery' },
    { id: 'T1482', name: 'Domain Trust Discovery' },
    { id: 'T1083', name: 'File/Dir Discovery' },
    { id: 'T1046', name: 'Network Service Scan' },
    { id: 'T1135', name: 'Network Share Discovery' },
    { id: 'T1040', name: 'Network Sniffing' },
    { id: 'T1201', name: 'Password Policy' },
    { id: 'T1120', name: 'Peripheral Device' },
    { id: 'T1069', name: 'Permission Groups' },
    { id: 'T1057', name: 'Process Discovery' },
    { id: 'T1012', name: 'Query Registry' },
    { id: 'T1018', name: 'Remote System Discovery' },
    { id: 'T1518', name: 'Software Discovery' },
    { id: 'T1082', name: 'System Info Discovery' },
    { id: 'T1016', name: 'System Network Config' },
    { id: 'T1049', name: 'System Network Conns' },
    { id: 'T1033', name: 'System Owner/User' },
    { id: 'T1007', name: 'System Service Discovery' },
    { id: 'T1124', name: 'System Time Discovery' },
  ]},
  { id: 'TA0008', name: 'Lateral Movement', techniques: [
    { id: 'T1210', name: 'Exploitation of Remote' },
    { id: 'T1534', name: 'Internal Spearphishing' },
    { id: 'T1570', name: 'Lateral Tool Transfer' },
    { id: 'T1563', name: 'Remote Service Hijack' },
    { id: 'T1021', name: 'Remote Services' },
    { id: 'T1091', name: 'Replication via Media' },
    { id: 'T1072', name: 'Software Deploy Tools' },
    { id: 'T1080', name: 'Taint Shared Content' },
    { id: 'T1550', name: 'Use Alternate Auth' },
  ]},
  { id: 'TA0009', name: 'Collection', techniques: [
    { id: 'T1557', name: 'Adversary-in-the-Middle' },
    { id: 'T1560', name: 'Archive Collected Data' },
    { id: 'T1123', name: 'Audio Capture' },
    { id: 'T1119', name: 'Automated Collection' },
    { id: 'T1185', name: 'Browser Session Hijack' },
    { id: 'T1115', name: 'Clipboard Data' },
    { id: 'T1530', name: 'Data from Cloud Storage' },
    { id: 'T1602', name: 'Data from Config Repo' },
    { id: 'T1213', name: 'Data from Info Repos' },
    { id: 'T1005', name: 'Data from Local System' },
    { id: 'T1039', name: 'Data from Network Share' },
    { id: 'T1025', name: 'Data from Removable' },
    { id: 'T1074', name: 'Data Staged' },
    { id: 'T1114', name: 'Email Collection' },
    { id: 'T1056', name: 'Input Capture' },
    { id: 'T1113', name: 'Screen Capture' },
    { id: 'T1125', name: 'Video Capture' },
  ]},
  { id: 'TA0011', name: 'Command & Control', techniques: [
    { id: 'T1071', name: 'Application Layer Proto' },
    { id: 'T1092', name: 'Communication via Media' },
    { id: 'T1132', name: 'Data Encoding' },
    { id: 'T1001', name: 'Data Obfuscation' },
    { id: 'T1568', name: 'Dynamic Resolution' },
    { id: 'T1573', name: 'Encrypted Channel' },
    { id: 'T1008', name: 'Fallback Channels' },
    { id: 'T1105', name: 'Ingress Tool Transfer' },
    { id: 'T1104', name: 'Multi-Stage Channels' },
    { id: 'T1095', name: 'Non-App Layer Proto' },
    { id: 'T1571', name: 'Non-Standard Port' },
    { id: 'T1572', name: 'Protocol Tunneling' },
    { id: 'T1090', name: 'Proxy' },
    { id: 'T1219', name: 'Remote Access Software' },
    { id: 'T1205', name: 'Traffic Signaling' },
    { id: 'T1102', name: 'Web Service' },
  ]},
  { id: 'TA0010', name: 'Exfiltration', techniques: [
    { id: 'T1020', name: 'Automated Exfiltration' },
    { id: 'T1030', name: 'Data Transfer Size' },
    { id: 'T1048', name: 'Exfil Over Alt Protocol' },
    { id: 'T1041', name: 'Exfil Over C2 Channel' },
    { id: 'T1011', name: 'Exfil Over Other Medium' },
    { id: 'T1052', name: 'Exfil Over Physical' },
    { id: 'T1567', name: 'Exfil Over Web Service' },
    { id: 'T1029', name: 'Scheduled Transfer' },
    { id: 'T1537', name: 'Transfer to Cloud Acct' },
  ]},
  { id: 'TA0040', name: 'Impact', techniques: [
    { id: 'T1531', name: 'Account Access Removal' },
    { id: 'T1485', name: 'Data Destruction' },
    { id: 'T1486', name: 'Data Encrypted Impact' },
    { id: 'T1565', name: 'Data Manipulation' },
    { id: 'T1491', name: 'Defacement' },
    { id: 'T1561', name: 'Disk Wipe' },
    { id: 'T1499', name: 'Endpoint DoS' },
    { id: 'T1495', name: 'Firmware Corruption' },
    { id: 'T1490', name: 'Inhibit System Recovery' },
    { id: 'T1498', name: 'Network DoS' },
    { id: 'T1496', name: 'Resource Hijacking' },
    { id: 'T1489', name: 'Service Stop' },
    { id: 'T1529', name: 'System Shutdown/Reboot' },
  ]},
]

/* ── SVG Progress Ring ─────────────────────────────────────────────────── */
function ProgressRing({ pct, size = 72, stroke = 6, color }: { pct: number; size?: number; stroke?: number; color: string }) {
  const r = (size - stroke) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (pct / 100) * circ
  return (
    <svg width={size} height={size} className="block">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-border, #e2e8f0)" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color}
        strokeWidth={stroke} strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
        transform={`rotate(-90 ${size / 2} ${size / 2})`} className="transition-all duration-700" />
      <text x="50%" y="50%" textAnchor="middle" dy="0.35em"
        className="text-[14px] font-bold" fill="var(--color-text-primary, #1a1d22)">
        {pct}%
      </text>
    </svg>
  )
}

/* ── Tactic bar chart data for top tactics ─────────────────────────────── */
const DONUT_COLORS = ['#22c55e', '#eab308', '#ef4444', '#94a3b8']

export function CoveragePage() {
  const [activeTactic, setActiveTactic] = useState<{ id: string; name: string } | null>(null)
  const [activeTechnique, setActiveTechnique] = useState<string | null>(null)
  const hasToken = !!localStorage.getItem('access_token')

  // Fetch finding logs when a tactic or technique is clicked
  const logsQueryKey = activeTechnique || activeTactic?.name || null
  const { data: tacticLogs, isLoading: logsLoading } = useQuery({
    queryKey: ['tactic-logs', logsQueryKey],
    queryFn: () => {
      if (activeTechnique) {
        return eventsApi.search({
          query: `technique_id:${activeTechnique} OR mitre_technique:${activeTechnique}`,
          time_range: '30d',
          limit: 50,
        })
      }
      return eventsApi.search({
        query: `tactic:${activeTactic!.name.toLowerCase().replace(/ /g, '_')} OR mitre_tactic:${activeTactic!.id}`,
        time_range: '30d',
        limit: 50,
      })
    },
    enabled: hasToken && (!!activeTactic || !!activeTechnique),
    staleTime: 30_000,
  })

  const { data: heatmap } = useQuery({
    queryKey: ['coverage-heatmap'],
    queryFn: () => overviewApi.heatmap(),
    staleTime: 60_000,
  })

  const { data: trend } = useQuery({
    queryKey: ['coverage-trend'],
    queryFn: () => coverageApi.trend(30),
    staleTime: 60_000,
  })

  // Compute coverage stats
  const stats = useMemo(() => {
    if (!heatmap) return { total: 0, covered: 0, pct: 0, byTactic: {} as Record<string, { covered: number; total: number }> }
    const totalTechniques = TACTICS.reduce((s, t) => s + t.techniques.length, 0)
    let total = 0
    let covered = 0
    const byTactic: Record<string, { covered: number; total: number }> = {}

    for (const row of heatmap) {
      for (const cell of row.cells) {
        total += cell.total
        covered += cell.covered
        if (!byTactic[cell.tactic]) byTactic[cell.tactic] = { covered: 0, total: 0 }
        byTactic[cell.tactic].covered += cell.covered
        byTactic[cell.tactic].total += cell.total
      }
    }

    return { total: totalTechniques, covered, pct: totalTechniques > 0 ? Math.round((covered / totalTechniques) * 100) : 0, byTactic }
  }, [heatmap])

  // Trend chart data
  const trendData = useMemo(() => {
    if (!trend?.points) return []
    return trend.points.map(p => ({
      date: new Date(p.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      pct: p.coverage_pct,
      covered: p.covered_count,
    }))
  }, [trend])

  // Donut chart data for coverage breakdown
  const donutData = useMemo(() => {
    const gaps = stats.total - stats.covered
    return [
      { name: 'Covered', value: stats.covered },
      { name: 'Gaps', value: gaps > 0 ? gaps : 0 },
    ]
  }, [stats])

  // Top 7 tactics by technique count for bar chart
  const topTacticData = useMemo(() => {
    return TACTICS
      .map(t => {
        const d = stats.byTactic[t.name] || { covered: 0, total: 0 }
        return { name: t.name.length > 14 ? t.name.slice(0, 12) + '…' : t.name, covered: d.covered, total: t.techniques.length }
      })
      .sort((a, b) => b.total - a.total)
      .slice(0, 7)
  }, [stats])

  const ringColor = stats.pct >= 80 ? '#22c55e' : stats.pct >= 60 ? '#eab308' : stats.pct > 0 ? '#ef4444' : '#94a3b8'

  return (
    <>
      <TopBar crumb="ATT&CK Matrix" />
      <div className="pt-[46px] flex h-[calc(100vh-46px)] overflow-hidden">

      {/* ═══ COLUMN 1: Left Panel — Coverage Stats ═══ */}
      <div className="w-[260px] shrink-0 border-r border-border bg-surface overflow-y-auto">

        {/* Coverage Ring */}
        <div className="p-3 border-b border-border">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">ATT&CK Coverage</p>
          <div className="flex items-center gap-3">
            <ProgressRing pct={stats.pct} color={ringColor} />
            <div className="space-y-1">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-[10px] text-text-muted">Covered</span>
                <span className="text-[11px] font-bold text-text-primary ml-auto">{stats.covered}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-border" />
                <span className="text-[10px] text-text-muted">Gaps</span>
                <span className="text-[11px] font-bold text-text-primary ml-auto">{stats.total - stats.covered}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue" />
                <span className="text-[10px] text-text-muted">Total</span>
                <span className="text-[11px] font-bold text-text-primary ml-auto">{stats.total}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Coverage by Tactic */}
        <div className="p-3 border-b border-border">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Coverage by Tactic</p>
          <div className="space-y-1.5">
            {TACTICS.map(tactic => {
              const data = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
              const pct = tactic.techniques.length > 0 ? Math.round((data.covered / tactic.techniques.length) * 100) : 0
              return (
                <button
                  key={tactic.id}
                  onClick={() => {
                    setActiveTactic(activeTactic?.id === tactic.id ? null : { id: tactic.id, name: tactic.name })
                    setActiveTechnique(null)
                  }}
                  className={`w-full text-left rounded px-1.5 py-0.5 transition-colors ${
                    activeTactic?.id === tactic.id ? 'bg-blue-light' : 'hover:bg-hover'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-text-primary truncate flex-1">{tactic.name}</span>
                    <span className="text-[9px] text-text-muted font-mono ml-1">{pct}%</span>
                  </div>
                  <div className="w-full h-1 rounded-full bg-border overflow-hidden mt-0.5">
                    <div
                      className={`h-full rounded-full transition-all ${pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : pct > 0 ? 'bg-red-500' : 'bg-border'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* Technique Distribution Donut */}
        <div className="p-3 border-b border-border">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Technique Distribution</p>
          <div className="flex items-center justify-center">
            <ResponsiveContainer width={80} height={80}>
              <PieChart>
                <Pie data={donutData} cx="50%" cy="50%" innerRadius={20} outerRadius={36}
                  dataKey="value" stroke="none">
                  <Cell fill="#22c55e" />
                  <Cell fill="var(--color-border, #e2e8f0)" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="ml-2 space-y-1">
              {donutData.map((d, i) => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: i === 0 ? '#22c55e' : 'var(--color-border, #e2e8f0)' }} />
                  <span className="text-[9px] text-text-muted">{d.name}</span>
                  <span className="text-[10px] font-bold text-text-primary ml-auto">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Tactics Bar */}
        <div className="p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Top Tactics by Size</p>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={topTacticData} layout="vertical" margin={{ left: 0, right: 8, top: 0, bottom: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 9, fill: 'var(--color-text-muted, #94a3b8)' }} width={85} />
              <Tooltip contentStyle={{ fontSize: 10, background: 'var(--color-surface, #fff)', border: '1px solid var(--color-border, #e2e8f0)', color: 'var(--color-text-primary, #1a1d22)' }} />
              <Bar dataKey="covered" stackId="a" fill="#22c55e" radius={[0, 0, 0, 0]} barSize={8} />
              <Bar dataKey="total" stackId="a" fill="var(--color-border, #e2e8f0)" radius={[0, 2, 2, 0]} barSize={8} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ═══ COLUMN 2: Center — KPIs + Matrix + Trend ═══ */}
      <div className="flex-1 min-w-0 border-r border-border overflow-y-auto">
        <div className="p-4 space-y-4">

          {/* KPI Cards */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-page border border-border rounded-lg p-3">
              <p className="text-[10px] text-text-muted uppercase tracking-wider">Coverage</p>
              <p className={`text-lg font-bold ${stats.pct >= 80 ? 'text-green-500' : stats.pct >= 60 ? 'text-yellow-500' : 'text-red-500'}`}>{stats.pct}%</p>
              <p className="text-[10px] text-text-muted">{stats.covered} of {stats.total} techniques</p>
            </div>
            <div className="bg-page border border-border rounded-lg p-3">
              <p className="text-[10px] text-text-muted uppercase tracking-wider">Tactics</p>
              <p className="text-lg font-bold text-text-primary">{TACTICS.length}</p>
              <p className="text-[10px] text-text-muted">MITRE ATT&CK Enterprise</p>
            </div>
            <div className="bg-page border border-border rounded-lg p-3">
              <p className="text-[10px] text-text-muted uppercase tracking-wider">Rules Active</p>
              <p className="text-lg font-bold text-text-primary">{heatmap?.length ?? 0}</p>
              <p className="text-[10px] text-text-muted">Sigma detection rules</p>
            </div>
          </div>

          {/* Coverage Trend Chart */}
          <div className="bg-page border border-border rounded-lg p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Coverage Trend (30d)</p>
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border, #e2e8f0)" opacity={0.3} />
                  <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'var(--color-text-muted, #94a3b8)' }} interval="preserveStartEnd" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: 'var(--color-text-muted, #94a3b8)' }} unit="%" width={32} />
                  <Tooltip contentStyle={{ fontSize: 10, background: 'var(--color-surface, #fff)', border: '1px solid var(--color-border, #e2e8f0)', color: 'var(--color-text-primary, #1a1d22)' }} />
                  <Area type="monotone" dataKey="pct" stroke="var(--color-primary, #0066CC)" fill="var(--color-primary, #0066CC)" fillOpacity={0.15} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[140px] flex items-center justify-center text-[11px] text-text-muted">No trend data</div>
            )}
          </div>

          {/* MITRE ATT&CK Enterprise Matrix */}
          <div className="bg-page border border-border rounded-lg p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">MITRE ATT&CK Enterprise Matrix</p>
            <div className="grid grid-cols-14 gap-[2px]" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(0, 1fr))` }}>
              {TACTICS.map(tactic => {
                const tacticData = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
                const tacticPct = tacticData.total > 0 ? Math.round((tacticData.covered / tacticData.total) * 100) : 0
                const slots = tactic.techniques.map(tech => {
                  const row = heatmap?.find(r => r.technique_id === tech.id)
                  const cell = row?.cells.find(c => c.tactic === tactic.name || c.covered > 0)
                  return { id: tech.id, name: tech.name, covered: cell ? cell.covered > 0 : false }
                })

                return (
                  <div key={tactic.id} className="flex flex-col min-w-0">
                    <button
                      onClick={() => {
                        setActiveTactic(activeTactic?.id === tactic.id ? null : { id: tactic.id, name: tactic.name })
                        setActiveTechnique(null)
                      }}
                      className={`px-0.5 py-1 rounded-t text-center border-b-2 w-full transition-colors cursor-pointer ${
                        activeTactic?.id === tactic.id ? 'bg-blue-light border-blue ring-1 ring-blue/30' :
                        tacticPct >= 80 ? 'bg-section border-green-500 hover:opacity-80' :
                        tacticPct >= 50 ? 'bg-section border-yellow-500 hover:opacity-80' :
                        tacticPct > 0 ? 'bg-section border-red-500 hover:opacity-80' :
                        'bg-section border-border hover:bg-hover'
                      }`}
                    >
                      <p className="text-[7px] font-bold text-text-primary leading-tight truncate" title={tactic.name}>{tactic.name}</p>
                      <p className="text-[6px] text-text-muted font-mono">{tactic.id}</p>
                    </button>
                    <div className="flex flex-col gap-[1px] mt-[1px]">
                      {slots.slice(0, 10).map((tech, i) => (
                        <button
                          key={i}
                          onClick={() => {
                            setActiveTechnique(activeTechnique === tech.id ? null : tech.id)
                            setActiveTactic(activeTechnique === tech.id ? null : { id: tactic.id, name: tactic.name })
                          }}
                          className={`px-0.5 py-[2px] rounded-[2px] cursor-pointer transition-colors text-left w-full ${
                            activeTechnique === tech.id
                              ? 'bg-blue-light text-blue ring-1 ring-blue/40'
                              : tech.covered
                                ? 'bg-resolved-bg text-resolved-text hover:opacity-80'
                                : 'bg-section text-text-muted hover:bg-hover'
                          }`}
                          title={`${tech.id}: ${tech.name}`}
                        >
                          <span className="block text-[6px] font-bold truncate">{tech.id}</span>
                          <span className="block text-[5px] leading-tight opacity-70 truncate">{tech.name}</span>
                        </button>
                      ))}
                      {slots.length > 10 && (
                        <div className="text-[6px] text-text-muted text-center py-0.5">+{slots.length - 10}</div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
            {/* Legend */}
            <div className="flex items-center gap-3 mt-2 text-[9px] text-text-muted">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-[2px] bg-resolved-bg border border-resolved-text/30" /> Covered</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-[2px] bg-section border border-border" /> Not Covered</span>
              <span className="ml-auto">Click tactic or technique to view findings</span>
            </div>
          </div>

        </div>
      </div>

      {/* ═══ COLUMN 3: Right Panel — Finding Logs ═══ */}
      <div className="w-[300px] shrink-0 overflow-y-auto bg-surface">
        <div className="p-4 space-y-4">

          {/* Finding Logs */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Finding Logs</p>
            {(!activeTactic && !activeTechnique) ? (
              <div className="border border-border rounded-lg p-4 bg-page">
                <div className="flex flex-col items-center justify-center h-40">
                  <div className="w-10 h-10 rounded-full bg-section flex items-center justify-center mb-2">
                    <span className="text-[16px] text-text-muted">?</span>
                  </div>
                  <p className="text-[11px] font-semibold text-text-primary mb-1">Select a Tactic or Technique</p>
                  <p className="text-[10px] text-text-muted text-center">Click on a tactic header or technique cell in the matrix to view related finding logs.</p>
                </div>
              </div>
            ) : (
              <div className="border border-border rounded-lg bg-page">
                <div className="flex items-center justify-between px-3 py-2 border-b border-border">
                  <h3 className="text-[11px] font-semibold text-text-primary truncate">
                    {activeTechnique ? (
                      <><span className="text-blue font-mono">{activeTechnique}</span><span className="text-text-muted ml-1">in {activeTactic?.name}</span></>
                    ) : (
                      <><span className="text-blue">{activeTactic!.name}</span><span className="text-text-muted font-mono ml-1">({activeTactic!.id})</span></>
                    )}
                  </h3>
                  <button
                    onClick={() => { setActiveTactic(null); setActiveTechnique(null) }}
                    className="text-[10px] text-text-muted hover:text-text-primary transition-colors ml-2 shrink-0"
                  >
                    Clear
                  </button>
                </div>
                <div className="p-2 max-h-[calc(100vh-260px)] overflow-y-auto">
                  {logsLoading ? (
                    <div className="flex items-center justify-center h-24 text-[11px] text-text-muted">Loading…</div>
                  ) : (() => {
                    const events = (tacticLogs?.events ?? []) as Record<string, unknown>[]
                    if (events.length === 0) {
                      return (
                        <div className="flex flex-col items-center justify-center h-24">
                          <p className="text-[11px] font-semibold text-text-primary mb-1">No findings</p>
                          <p className="text-[10px] text-text-muted">No events in the last 30 days.</p>
                        </div>
                      )
                    }
                    return (
                      <div className="space-y-1.5">
                        {events.slice(0, 30).map((evt, i) => {
                          const raw = (evt.raw ?? evt) as Record<string, unknown>
                          const time = String(raw.time ?? evt.time ?? '').slice(11, 19)
                          const summary = String(raw.summary ?? (raw as Record<string, unknown>).unmapped?.summary ?? evt.summary ?? evt.class_name ?? '—')
                          const host = String((raw.src_endpoint as Record<string, unknown>)?.hostname ?? raw.hostname ?? evt.hostname ?? evt.src_ip ?? '—')
                          const severity = Number(raw.severity_id ?? evt.severity_id ?? 0)
                          const sevColor = severity >= 4 ? 'border-l-red-500' : severity >= 3 ? 'border-l-yellow-500' : severity >= 2 ? 'border-l-blue' : 'border-l-border'
                          return (
                            <div key={i} className={`border-l-2 ${sevColor} bg-surface rounded-r px-2 py-1.5 hover:bg-hover/50 transition-colors`}>
                              <div className="flex items-center justify-between">
                                <span className="text-[9px] font-mono text-text-muted">{time}</span>
                                <span className="text-[8px] font-mono text-text-muted truncate ml-2">{host}</span>
                              </div>
                              <p className="text-[10px] text-text-primary truncate mt-0.5" title={summary}>{summary}</p>
                            </div>
                          )
                        })}
                        {events.length > 30 && (
                          <p className="text-center text-[9px] text-text-muted pt-1">+{events.length - 30} more</p>
                        )}
                      </div>
                    )
                  })()}
                </div>
              </div>
            )}
          </div>

          {/* Quick Navigation */}
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Quick Navigation</p>
            <div className="border border-border rounded-lg bg-page divide-y divide-border">
              {[
                { href: '/hunt', label: 'Hunt', desc: 'Search detections & alerts' },
                { href: '/ndr', label: 'NDR Logs', desc: 'Network flow analysis' },
                { href: '/sources', label: 'Data Sources', desc: 'Manage connectors' },
                { href: '/settings', label: 'Settings', desc: 'Users & system config' },
              ].map(link => (
                <a key={link.href} href={link.href}
                  className="flex items-center justify-between px-3 py-2 hover:bg-hover transition-colors">
                  <div>
                    <p className="text-[11px] font-medium text-text-primary">{link.label}</p>
                    <p className="text-[9px] text-text-muted">{link.desc}</p>
                  </div>
                  <span className="text-[10px] text-text-muted">&rarr;</span>
                </a>
              ))}
            </div>
          </div>

        </div>
      </div>

      </div>
    </>
  )
}
