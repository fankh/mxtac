import { http, HttpResponse } from 'msw'

const BASE = '/api/v1'

export const handlers = [
  // Auth
  http.post(`${BASE}/auth/login`, async ({ request }) => {
    const body = await request.json() as { email: string; password: string }
    if (body.email === 'analyst@mxtac.local' && body.password === 'mxtac2026') {
      return HttpResponse.json({
        access_token: 'mock-token-abc123',
        token_type: 'bearer',
        email: 'analyst@mxtac.local',
        role: 'analyst',
      })
    }
    return HttpResponse.json({ detail: 'Invalid credentials' }, { status: 401 })
  }),

  // Overview KPIs
  http.get(`${BASE}/overview/kpis`, () =>
    HttpResponse.json({
      total_detections: 4821,
      total_detections_delta_pct: 12,
      critical_alerts: 23,
      critical_alerts_new_today: 5,
      attack_covered: 187,
      attack_total: 740,
      attack_coverage_delta: 4,
      mttd_minutes: 8,
      mttd_delta_minutes: -2,
      integrations_active: 6,
      integrations_total: 8,
      sigma_rules_active: 1247,
      sigma_rules_critical: 89,
      sigma_rules_high: 312,
      sigma_rules_deployed_this_week: 14,
    }),
  ),

  // Detections list
  http.get(`${BASE}/detections`, () =>
    HttpResponse.json({
      items: [
        {
          id: 'det-001',
          score: 9.2,
          severity: 'critical',
          technique_id: 'T1003.001',
          technique_name: 'LSASS Memory Dump',
          tactic: 'Credential Access',
          name: 'Suspicious LSASS Memory Access',
          host: 'WIN-DC01',
          status: 'active',
          time: '2026-02-19T08:30:00Z',
          rule_name: 'proc_access_win_lsass_dump_tools_dll',
        },
      ],
      pagination: { page: 1, page_size: 20, total: 1, total_pages: 1 },
    }),
  ),

  // Detection detail
  http.get(`${BASE}/detections/:id`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      score: 9.2,
      severity: 'critical',
      technique_id: 'T1003.001',
      technique_name: 'LSASS Memory Dump',
      tactic: 'Credential Access',
      name: 'Suspicious LSASS Memory Access',
      host: 'WIN-DC01',
      status: 'active',
      time: '2026-02-19T08:30:00Z',
    }),
  ),

  // Detection update
  http.patch(`${BASE}/detections/:id`, async ({ params, request }) => {
    const body = await request.json() as Record<string, unknown>
    return HttpResponse.json({
      id: params.id,
      score: 9.2,
      severity: 'critical',
      technique_id: 'T1003.001',
      technique_name: 'LSASS Memory Dump',
      tactic: 'Credential Access',
      name: 'Suspicious LSASS Memory Access',
      host: 'WIN-DC01',
      status: body.status ?? 'active',
      assigned_to: body.assigned_to ?? null,
      time: '2026-02-19T08:30:00Z',
    })
  }),
]
