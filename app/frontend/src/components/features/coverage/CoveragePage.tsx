import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { overviewApi, coverageApi, eventsApi } from '../../../lib/api'
import type { HeatRow, CoverageTrend } from '../../../types/api'
import { SeverityPill } from '../../shared/SeverityBadge'
import { TopBar } from '../../layout/TopBar'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
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

export function CoveragePage() {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null)
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

  const { data: heatmap, isLoading: heatmapLoading } = useQuery({
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

  return (
    <>
      <TopBar crumb="ATT&CK Matrix" />
      <div className="pt-[46px] px-5 pb-6">

      {/* Search bar + tactic filter chips — matches Hunt/NDR layout */}
      <div className="flex items-center gap-2 py-3 flex-wrap">
        <div className="relative flex-1 min-w-[280px]">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted text-[13px] select-none">⌕</span>
          <input
            type="text"
            value={selectedTactic ?? ''}
            onChange={e => setSelectedTactic(e.target.value || null)}
            placeholder="Filter by tactic — e.g. Execution, Persistence, Lateral Movement"
            className="w-full h-[32px] pl-8 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
          />
        </div>
        <div className="flex items-center border border-border rounded-md overflow-hidden">
          {['All', 'Covered', 'Gaps'].map(f => (
            <button
              key={f}
              className={`px-3 h-[32px] text-[11px] font-medium border-r border-border last:border-r-0 transition-colors ${
                (f === 'All' && !selectedTactic) ? 'bg-blue text-white' : 'bg-surface text-text-secondary hover:bg-page'
              }`}
              onClick={() => setSelectedTactic(f === 'All' ? null : f === 'Covered' ? 'covered' : 'gaps')}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Stats bar */}
      <div className="flex items-center gap-3 text-[11px] text-text-muted mb-3">
        <span className={`font-bold text-[14px] ${stats.pct >= 80 ? 'text-green-500' : stats.pct >= 60 ? 'text-yellow-500' : 'text-red-500'}`}>
          {stats.pct}%
        </span>
        <span>coverage</span>
        <span>·</span>
        <span><strong className="text-text-primary">{stats.covered}</strong> / {stats.total} techniques</span>
        <span>·</span>
        <span><strong className="text-text-primary">{heatmap?.length ?? 0}</strong> rules mapped</span>
        <span>·</span>
        <span><strong className="text-text-primary">{TACTICS.length}</strong> tactics</span>
      </div>

      {/* Coverage Trend — full width, single column */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-4">
        <h2 className="text-[11px] font-semibold mb-3">Coverage Trend (30 days)</h2>
        {trendData.length > 0 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.3} />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--color-muted)' }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--color-muted)' }} unit="%" />
              <Tooltip contentStyle={{ fontSize: 11, background: 'var(--color-surface)', border: '1px solid var(--color-border)' }} />
              <Area type="monotone" dataKey="pct" stroke="var(--color-blue)" fill="var(--color-blue)" fillOpacity={0.1} strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[160px] flex items-center justify-center text-[11px] text-text-muted">No trend data</div>
        )}
      </div>

      {/* Tactic Breakdown — horizontal bar list, single column */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-4">
        <h2 className="text-[11px] font-semibold mb-3">Coverage by Tactic</h2>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
          {TACTICS.map(tactic => {
            const data = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
            const pct = data.total > 0 ? Math.round((data.covered / data.total) * 100) : 0
            return (
              <div key={tactic.id} className="flex items-center gap-2">
                <span className="text-[10px] text-text-muted font-mono w-[46px] shrink-0">{tactic.id}</span>
                <span className="text-[11px] flex-1 truncate">{tactic.name}</span>
                <div className="w-[80px] h-1.5 rounded-full bg-border overflow-hidden shrink-0">
                  <div
                    className={`h-full rounded-full ${pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : pct > 0 ? 'bg-red-500' : 'bg-border'}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-[10px] font-medium w-[28px] text-right text-text-muted">{pct}%</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Matrix + Finding Logs side by side */}
      <div className="flex gap-3">

      {/* MITRE ATT&CK Enterprise Matrix */}
      <div className={`bg-surface border border-border rounded-lg p-4 ${(activeTactic || activeTechnique) ? 'flex-1 min-w-0' : 'w-full'} transition-all`}>
        <h2 className="text-[11px] font-semibold mb-3">MITRE ATT&CK Enterprise Matrix</h2>
        <div className="overflow-x-auto">
          <div className="flex gap-[3px] min-w-max">
            {TACTICS.map(tactic => {
              const tacticData = stats.byTactic[tactic.name] || { covered: 0, total: 0 }
              const tacticPct = tacticData.total > 0 ? Math.round((tacticData.covered / tacticData.total) * 100) : 0
              // Use real techniques from ATT&CK data, check coverage from heatmap
              const slots = tactic.techniques.map(tech => {
                const row = heatmap?.find(r => r.technique_id === tech.id)
                const cell = row?.cells.find(c => c.tactic === tactic.name || c.covered > 0)
                return { id: tech.id, name: tech.name, covered: cell ? cell.covered > 0 : false }
              })

              return (
                <div key={tactic.id} className="flex flex-col w-[105px] shrink-0">
                  {/* Tactic header — click to show finding logs */}
                  <button
                    onClick={() => setActiveTactic(activeTactic?.id === tactic.id ? null : { id: tactic.id, name: tactic.name })}
                    className={`px-2 py-1.5 rounded-t text-center border-b-2 w-full transition-colors cursor-pointer ${
                      activeTactic?.id === tactic.id ? 'bg-blue/10 border-blue ring-1 ring-blue/30' :
                      tacticPct >= 80 ? 'bg-green-500/10 border-green-500 hover:bg-green-500/20' :
                      tacticPct >= 50 ? 'bg-yellow-500/10 border-yellow-500 hover:bg-yellow-500/20' :
                      tacticPct > 0 ? 'bg-red-500/10 border-red-500 hover:bg-red-500/20' :
                      'bg-page border-border hover:bg-hover'
                    }`}
                  >
                    <p className="text-[9px] font-bold text-text-primary leading-tight truncate" title={tactic.name}>{tactic.name}</p>
                    <p className="text-[8px] text-text-muted font-mono">{tactic.id}</p>
                  </button>
                  {/* Technique cells */}
                  <div className="flex flex-col gap-[2px] mt-[2px]">
                    {slots.slice(0, 12).map((tech, i) => (
                      <button
                        key={i}
                        onClick={() => {
                          setActiveTechnique(activeTechnique === tech.id ? null : tech.id)
                          setActiveTactic(activeTechnique === tech.id ? null : { id: tactic.id, name: tactic.name })
                        }}
                        className={`px-1.5 py-[3px] rounded-[3px] cursor-pointer transition-colors text-left w-full ${
                          activeTechnique === tech.id
                            ? 'bg-blue/20 text-blue ring-1 ring-blue/40'
                            : tech.covered
                              ? 'bg-green-500/20 text-green-700 hover:bg-green-500/30'
                              : 'bg-page text-text-muted/50 hover:bg-border/30'
                        }`}
                        title={`${tech.id}: ${tech.name}`}
                      >
                        <span className="block text-[8px] font-bold">{tech.id}</span>
                        <span className="block text-[7px] leading-tight opacity-70 truncate">{tech.name}</span>
                      </button>
                    ))}
                    {slots.length > 12 && (
                      <div className="text-[8px] text-text-muted text-center py-0.5">+{slots.length - 12} more</div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 mt-3 text-[10px] text-text-muted">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-green-500/20 border border-green-500/30" /> Covered</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-[2px] bg-page border border-border" /> Not Covered</span>
          <span className="ml-auto text-text-muted">Click tactic or technique to view finding logs</span>
        </div>
      </div>

      {/* Finding Logs — right side panel */}
      {(activeTactic || activeTechnique) && (
        <div className="w-[30%] shrink-0 bg-surface border border-border rounded-lg p-4 overflow-y-auto max-h-[600px]">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[11px] font-semibold">
              Finding Logs — {activeTechnique ? (
                <>
                  <span className="text-blue font-mono">{activeTechnique}</span>
                  <span className="text-text-muted ml-1">in {activeTactic?.name}</span>
                </>
              ) : (
                <>
                  <span className="text-blue">{activeTactic!.name}</span>
                  <span className="text-text-muted font-mono ml-1">({activeTactic!.id})</span>
                </>
              )}
            </h2>
            <button
              onClick={() => { setActiveTactic(null); setActiveTechnique(null) }}
              className="text-[10px] text-text-muted hover:text-text-primary transition-colors"
            >
              ✕ Close
            </button>
          </div>

          {logsLoading ? (
            <div className="flex items-center justify-center h-32 text-[11px] text-text-muted">Loading logs…</div>
          ) : (() => {
            const events = (tacticLogs?.events ?? []) as Record<string, unknown>[]
            if (events.length === 0) {
              return (
                <div className="flex flex-col items-center justify-center h-32">
                  <p className="text-[12px] font-semibold text-text-primary mb-1">No findings for {activeTechnique || activeTactic?.name}</p>
                  <p className="text-[10px] text-text-muted">No events matched this {activeTechnique ? 'technique' : 'tactic'} in the last 30 days.</p>
                </div>
              )
            }
            return (
              <div className="space-y-1.5">
                {events.slice(0, 20).map((evt, i) => {
                  const raw = (evt.raw ?? evt) as Record<string, unknown>
                  const time = String(raw.time ?? evt.time ?? '').slice(11, 19)
                  const summary = String(raw.summary ?? (raw as Record<string, unknown>).unmapped?.summary ?? evt.summary ?? evt.class_name ?? '—')
                  const host = String((raw.src_endpoint as Record<string, unknown>)?.hostname ?? raw.hostname ?? evt.hostname ?? evt.src_ip ?? '—')
                  const severity = Number(raw.severity_id ?? evt.severity_id ?? 0)
                  const sevColor = severity >= 4 ? 'border-l-red-500' : severity >= 3 ? 'border-l-yellow-500' : severity >= 2 ? 'border-l-blue' : 'border-l-border'
                  return (
                    <div key={i} className={`border-l-2 ${sevColor} bg-page rounded-r px-2 py-1.5 hover:bg-hover/50 transition-colors`}>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-text-muted">{time}</span>
                        <span className="text-[9px] font-mono text-text-muted">{host}</span>
                      </div>
                      <p className="text-[10px] text-text-primary truncate mt-0.5" title={summary}>{summary}</p>
                    </div>
                  )
                })}
                {events.length > 20 && (
                  <p className="text-center text-[9px] text-text-muted pt-1">+{events.length - 20} more findings</p>
                )}
              </div>
            )
          })()}
        </div>
      )}
      </div>{/* end flex row */}
    </div>
    </>
  )
}
