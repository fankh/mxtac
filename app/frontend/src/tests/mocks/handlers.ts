import { http, HttpResponse } from 'msw'

const BASE = '/api/v1'

/** One detection in the shape GET /detections returns (unset detail fields are null). */
const MOCK_DETECTION = {
  id: 'det-001',
  score: 9.2,
  severity: 'critical',
  technique_id: 'T1003.001',
  technique_name: 'LSASS Memory Dump',
  name: 'Suspicious LSASS Memory Access',
  host: 'WIN-DC01',
  tactic: 'Credential Access',
  status: 'active',
  time: '2026-02-19T08:30:00Z',
  user: null,
  process: null,
  rule_name: 'proc_access_win_lsass_dump_tools_dll',
  log_source: null,
  event_id: null,
  occurrence_count: null,
  description: null,
  cvss_v3: null,
  confidence: null,
  tactic_id: 'TA0006',
  related_technique_ids: [],
  assigned_to: null,
  priority: null,
}

const MOCK_INCIDENT_NOTE = {
  id: '2f9d3c6a-8f41-4c0e-b1d7-6a5e94c0d3f8',
  author: 'analyst@mxtac.local',
  content: 'Memory image collected from WIN-DC01.',
  note_type: 'evidence',
  created_at: '2026-02-19T09:20:00+00:00',
}

const MOCK_INCIDENT = {
  id: 1,
  title: 'Credential theft on the domain controller',
  description: null,
  severity: 'critical',
  status: 'new',
  priority: 3,
  assigned_to: null,
  created_by: 'analyst@mxtac.local',
  detection_ids: ['det-001'],
  technique_ids: ['T1003.001'],
  tactic_ids: ['TA0006'],
  hosts: ['WIN-DC01'],
  ttd_seconds: 120,
  ttr_seconds: null,
  closed_at: null,
  created_at: '2026-02-19T09:00:00Z',
  updated_at: '2026-02-19T09:00:00Z',
}

/** Session answer of POST /auth/login, /auth/change-password and /auth/mfa/verify. */
const MOCK_SESSION = {
  access_token: 'mock-token-abc123',
  refresh_token: 'mock-refresh-token-abc123',
  token_type: 'bearer',
  expires_in: 3600,
  email: 'analyst@mxtac.local',
  role: 'analyst',
}

export const handlers = [
  // Auth
  http.post(`${BASE}/auth/login`, async ({ request }) => {
    const body = await request.json() as { email: string; password: string }
    if (body.email === 'analyst@mxtac.local' && body.password === 'Analyst-Passw0rd') {
      return HttpResponse.json(MOCK_SESSION)
    }
    // An account created with a temporary password must set a new one first.
    if (body.email === 'new@mxtac.local' && body.password === 'Temp-Passw0rd') {
      return HttpResponse.json({ password_change_required: true, password_change_token: 'mock-password-change-token' })
    }
    return HttpResponse.json({ detail: 'Invalid credentials' }, { status: 401 })
  }),
  http.post(`${BASE}/auth/change-password`, async ({ request }) => {
    const body = await request.json() as { password_change_token: string; new_password: string; confirm_password: string }
    if (body.password_change_token !== 'mock-password-change-token') {
      return HttpResponse.json({ detail: 'Invalid or expired token' }, { status: 401 })
    }
    if (body.new_password === 'Temp-Passw0rd') {
      return HttpResponse.json({ detail: 'Cannot reuse one of your last 2 passwords' }, { status: 400 })
    }
    return HttpResponse.json({ ...MOCK_SESSION, email: 'new@mxtac.local' })
  }),
  http.post(`${BASE}/auth/password`, async ({ request }) => {
    const body = await request.json() as { current_password: string; new_password: string }
    if (body.current_password !== 'Analyst-Passw0rd') {
      return HttpResponse.json({ detail: 'Current password is incorrect' }, { status: 400 })
    }
    return new HttpResponse(null, { status: 204 })
  }),

  // Overview KPIs
  http.get(`${BASE}/overview/kpis`, () =>
    HttpResponse.json({
      total_detections: 4821,
      total_detections_delta_pct: 12,
      critical_alerts: 23,
      critical_alerts_new_today: 5,
      attack_coverage_pct: 25,
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
      open_incidents_count: 3,
      mttr_minutes: 210,
    }),
  ),

  // Detections list
  http.get(`${BASE}/detections`, () =>
    HttpResponse.json({
      items: [MOCK_DETECTION],
      pagination: { page: 1, page_size: 25, total: 1, total_pages: 1 },
    }),
  ),

  // Detections CSV export (registered before /detections/:id so "export" is not read as an ID)
  http.get(`${BASE}/detections/export`, () =>
    new HttpResponse(
      'id,name,severity,tactic,technique_id,host,status,score,time\r\n' +
        'det-001,Suspicious LSASS Memory Access,critical,Credential Access,T1003.001,WIN-DC01,active,9.2,2026-02-19T08:30:00+00:00\r\n',
      {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="detections_2026-02-19.csv"',
        },
      },
    ),
  ),

  // Detection detail
  http.get(`${BASE}/detections/:id`, ({ params }) =>
    HttpResponse.json({ ...MOCK_DETECTION, id: params.id }),
  ),

  // Detection bulk status update
  http.post(`${BASE}/detections/bulk`, async ({ request }) => {
    const body = await request.json() as { ids: string[]; status: string }
    return HttpResponse.json({ updated: body.ids.length, not_found: [] })
  }),

  // Detection update
  http.patch(`${BASE}/detections/:id`, async ({ params, request }) => {
    const body = await request.json() as { status?: string; assigned_to?: string; priority?: string }
    return HttpResponse.json({
      ...MOCK_DETECTION,
      id: params.id,
      status: body.status ?? MOCK_DETECTION.status,
      assigned_to: body.assigned_to ?? null,
      priority: body.priority ?? null,
    })
  }),

  // Detection delete
  http.delete(`${BASE}/detections/:id`, () => new HttpResponse(null, { status: 204 })),

  // Incidents list
  http.get(`${BASE}/incidents`, () =>
    HttpResponse.json({
      items: [MOCK_INCIDENT],
      pagination: { page: 1, page_size: 20, total: 1, total_pages: 1 },
    }),
  ),

  // Incident create
  http.post(`${BASE}/incidents`, async ({ request }) => {
    const body = await request.json() as {
      title: string
      severity: string
      description?: string | null
      assigned_to?: string | null
      detection_ids?: string[]
    }
    return HttpResponse.json(
      {
        ...MOCK_INCIDENT,
        id: 2,
        title: body.title,
        severity: body.severity,
        description: body.description ?? null,
        assigned_to: body.assigned_to ?? null,
        detection_ids: body.detection_ids ?? [],
      },
      { status: 201 },
    )
  }),

  // Incident metrics (registered before /incidents/:id)
  http.get(`${BASE}/incidents/metrics`, () =>
    HttpResponse.json({
      total_incidents: { new: 1, investigating: 0, contained: 0, resolved: 0, closed: 0 },
      mttr_seconds: null,
      mttd_seconds: 120,
      open_incidents_count: 1,
      incidents_by_severity: { critical: 1, high: 0, medium: 0, low: 0 },
      incidents_this_week: 1,
      incidents_this_month: 1,
      from_date: '2026-01-20T09:00:00Z',
      to_date: '2026-02-19T09:00:00Z',
    }),
  ),

  // Incident detail
  http.get(`${BASE}/incidents/:id`, ({ params }) =>
    HttpResponse.json({
      ...MOCK_INCIDENT,
      id: Number(params.id),
      detections: [MOCK_DETECTION],
      notes: [MOCK_INCIDENT_NOTE],
      duration_seconds: 1800,
    }),
  ),

  // Incident update
  http.patch(`${BASE}/incidents/:id`, async ({ params, request }) => {
    const body = await request.json() as Record<string, unknown>
    return HttpResponse.json({ ...MOCK_INCIDENT, ...body, id: Number(params.id) })
  }),

  // Incident delete (soft: the backend closes the incident)
  http.delete(`${BASE}/incidents/:id`, () => new HttpResponse(null, { status: 204 })),

  // Incident notes
  http.get(`${BASE}/incidents/:id/notes`, () => HttpResponse.json([MOCK_INCIDENT_NOTE])),

  http.post(`${BASE}/incidents/:id/notes`, async ({ request }) => {
    const body = await request.json() as { content: string; note_type?: string }
    return HttpResponse.json(
      {
        id: '7b0f6c1e-52a4-4f0b-9a57-3d0a1c8e6b42',
        author: 'analyst@mxtac.local',
        content: body.content,
        note_type: body.note_type ?? 'comment',
        created_at: '2026-02-19T09:45:00+00:00',
      },
      { status: 201 },
    )
  }),

  // Rules list
  http.get(`${BASE}/rules`, () =>
    HttpResponse.json([
      {
        id: 'rule-001',
        title: 'Suspicious LSASS Memory Access',
        level: 'high',
        status: 'experimental',
        enabled: true,
        technique_ids: ['T1003.001'],
        tactic_ids: ['credential_access'],
        logsource: { product: 'windows', category: 'process_access' },
        hit_count: 0,
        fp_count: 0,
      },
    ]),
  ),

  // Rule create
  http.post(`${BASE}/rules`, async ({ request }) => {
    const body = await request.json() as Record<string, unknown>
    return HttpResponse.json(
      {
        id: 'rule-new',
        title: body.title ?? 'New Rule',
        level: 'high',
        status: 'experimental',
        enabled: true,
        technique_ids: [],
        tactic_ids: [],
        logsource: {},
        hit_count: 0,
        fp_count: 0,
      },
      { status: 201 },
    )
  }),

  // Rules: stats, detail, update, delete, import, reload, test, false positive
  http.get(`${BASE}/rules/stats/summary`, () =>
    HttpResponse.json({ total: 1, enabled: 1, by_level: { high: 1 } }),
  ),
  http.get(`${BASE}/rules/:id`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      title: 'Suspicious LSASS Memory Access',
      level: 'high',
      status: 'experimental',
      enabled: true,
      technique_ids: ['T1003.001'],
      tactic_ids: ['credential_access'],
      logsource: { product: 'windows', category: 'process_access' },
      hit_count: 0,
      fp_count: 0,
      content: 'title: Suspicious LSASS Memory Access\ndetection:\n  selection:\n    EventID: 10\n  condition: selection\nlevel: high\n',
      description: '',
      source: 'custom',
      created_by: null,
    }),
  ),
  http.patch(`${BASE}/rules/:id`, async ({ params, request }) => {
    const body = await request.json() as { enabled?: boolean; content?: string }
    return HttpResponse.json({
      id: params.id,
      title: 'Suspicious LSASS Memory Access',
      level: 'high',
      status: 'experimental',
      enabled: body.enabled ?? true,
      technique_ids: ['T1003.001'],
      tactic_ids: ['credential_access'],
      logsource: { product: 'windows', category: 'process_access' },
      hit_count: 0,
      fp_count: 0,
    })
  }),
  http.delete(`${BASE}/rules/:id`, () => new HttpResponse(null, { status: 204 })),
  http.post(`${BASE}/rules/import`, () => HttpResponse.json({ imported: 1, total_rules: 2 })),
  http.post(`${BASE}/rules/reload`, () => HttpResponse.json({ reloaded: 1, total_rules: 1 })),
  http.post(`${BASE}/rules/test`, () => HttpResponse.json({ matched: true, errors: [] })),
  http.post(`${BASE}/rules/:id/test`, () => HttpResponse.json({ matched: false, errors: [] })),
  http.post(`${BASE}/rules/:id/mark_fp`, ({ params }) =>
    HttpResponse.json({ rule_id: params.id, status: 'marked' }),
  ),

  // Connectors (data sources)
  http.get(`${BASE}/connectors`, () =>
    HttpResponse.json([
      {
        id: 'conn-001',
        name: 'wazuh-prod',
        connector_type: 'wazuh',
        status: 'active',
        enabled: true,
        events_total: 1200,
        errors_total: 0,
        last_seen_at: '2026-02-19T08:30:00+00:00',
        error_message: null,
      },
    ]),
  ),
  http.post(`${BASE}/connectors`, async ({ request }) => {
    const body = await request.json() as { name: string; connector_type: string; enabled?: boolean }
    return HttpResponse.json(
      {
        id: 'conn-new',
        name: body.name,
        connector_type: body.connector_type,
        status: 'inactive',
        enabled: body.enabled ?? true,
        events_total: 0,
        errors_total: 0,
        last_seen_at: null,
        error_message: null,
      },
      { status: 201 },
    )
  }),
  http.patch(`${BASE}/connectors/:id`, async ({ params, request }) => {
    const body = await request.json() as { enabled?: boolean }
    return HttpResponse.json({
      id: params.id,
      name: 'wazuh-prod',
      connector_type: 'wazuh',
      status: 'active',
      enabled: body.enabled ?? true,
      events_total: 1200,
      errors_total: 0,
      last_seen_at: '2026-02-19T08:30:00+00:00',
      error_message: null,
    })
  }),
  http.delete(`${BASE}/connectors/:id`, () => new HttpResponse(null, { status: 204 })),
  http.get(`${BASE}/connectors/:id/health`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      name: 'wazuh-prod',
      connector_type: 'wazuh',
      status: 'active',
      enabled: true,
      healthy: true,
      events_total: 1200,
      errors_total: 0,
      last_seen_at: '2026-02-19T08:30:00+00:00',
      error_message: null,
    }),
  ),
  http.post(`${BASE}/connectors/:id/start`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      name: 'wazuh-prod',
      connector_type: 'wazuh',
      status: 'connecting',
      enabled: true,
      events_total: 1200,
      errors_total: 0,
      last_seen_at: null,
      error_message: null,
    }),
  ),
  http.post(`${BASE}/connectors/:id/stop`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      name: 'wazuh-prod',
      connector_type: 'wazuh',
      status: 'inactive',
      enabled: true,
      events_total: 1200,
      errors_total: 0,
      last_seen_at: null,
      error_message: null,
    }),
  ),
  http.post(`${BASE}/connectors/:id/test`, ({ params }) =>
    HttpResponse.json({
      connector_id: params.id,
      reachable: true,
      message: 'Wazuh API reachable and credentials valid',
    }),
  ),

  // Webhook ingest (generic sources)
  http.post(`${BASE}/ingest`, () => HttpResponse.json({ accepted: 1, rejected: 0 }, { status: 202 })),

  // Current user and admin user management
  http.get(`${BASE}/auth/me`, () =>
    HttpResponse.json({ email: 'admin@mxtac.local', role: 'admin', full_name: 'Ada Admin', mfa_enabled: false }),
  ),
  http.post(`${BASE}/auth/mfa/disable`, () => HttpResponse.json({ message: 'MFA disabled' })),
  http.get(`${BASE}/users`, () =>
    HttpResponse.json([
      {
        id: '5b0c7c0e-6f0b-4f65-9a54-2c3b1d0e8a11',
        email: 'admin@mxtac.local',
        full_name: 'Ada Admin',
        role: 'admin',
        is_active: true,
        mfa_enabled: false,
        must_change_password: false,
      },
      {
        id: 'd2a9f3b4-18c7-4e2a-b6d1-7f40c9e5a3c2',
        email: 'analyst@mxtac.local',
        full_name: null,
        role: 'analyst',
        is_active: true,
        mfa_enabled: true,
        must_change_password: false,
      },
    ]),
  ),
  http.post(`${BASE}/users`, async ({ request }) => {
    const body = await request.json() as { email: string; full_name?: string | null; role?: string }
    return HttpResponse.json(
      {
        id: '9e4b1a6d-3c52-4f0e-8d7a-1b6c2f9a4e30',
        email: body.email,
        full_name: body.full_name ?? null,
        role: body.role ?? 'analyst',
        is_active: true,
        mfa_enabled: false,
        must_change_password: true,
      },
      { status: 201 },
    )
  }),
  http.patch(`${BASE}/users/:id`, async ({ params, request }) => {
    const body = await request.json() as { full_name?: string; role?: string; is_active?: boolean }
    return HttpResponse.json({
      id: params.id,
      email: 'analyst@mxtac.local',
      full_name: body.full_name ?? null,
      role: body.role ?? 'analyst',
      is_active: body.is_active ?? true,
      mfa_enabled: true,
      must_change_password: false,
    })
  }),
  http.delete(`${BASE}/users/:id`, () => new HttpResponse(null, { status: 204 })),

  // Events (hunt)
  http.post(`${BASE}/events/search`, async ({ request }) => {
    const body = await request.json() as { size?: number; from_?: number }
    return HttpResponse.json({
      total: 1,
      items: [
        {
          id: '1aa9e407-9bd6-451f-a144-e23eaec6c792',
          event_uid: 'evt-001',
          time: '2026-02-19T08:30:00+00:00',
          class_name: 'Process Activity',
          class_uid: 1007,
          severity_id: 4,
          src_ip: '10.0.0.5',
          dst_ip: null,
          hostname: 'WIN-DC01',
          username: 'svc-backup',
          process_hash: null,
          source: 'wazuh',
          summary: 'powershell.exe spawned by winword.exe',
        },
      ],
      from_: body.from_ ?? 0,
      size: body.size ?? 100,
      backend: 'postgres',
    })
  }),

  http.post(`${BASE}/events/aggregate`, async ({ request }) => {
    const body = await request.json() as { agg_type?: string; field?: string; interval?: string }
    if (body.agg_type === 'date_histogram') {
      return HttpResponse.json({
        agg_type: 'date_histogram',
        interval: body.interval ?? '1h',
        buckets: [{ key: '2026-02-19T08:00:00+00:00', count: 1 }],
      })
    }
    return HttpResponse.json({ field: body.field ?? null, buckets: [{ key: 'wazuh', count: 1 }] })
  }),

  http.post(`${BASE}/events/query-dsl`, () =>
    HttpResponse.json({ lucene: 'time:[now-24h TO now]' }),
  ),

  http.post(`${BASE}/events/export`, () =>
    new HttpResponse('id,time,class_name,severity_id,src_ip,dst_ip,hostname,username,source,summary\n', {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="events_2026-02-19.csv"',
      },
    }),
  ),

  http.get(`${BASE}/events/entity/:type/:value`, ({ params }) =>
    HttpResponse.json({
      entity_type: params.type,
      entity_value: params.value,
      total: 0,
      events: [],
    }),
  ),

  http.get(`${BASE}/events/:id`, ({ params }) =>
    HttpResponse.json({
      id: params.id,
      event_uid: 'evt-001',
      time: '2026-02-19T08:30:00+00:00',
      class_name: 'Process Activity',
      class_uid: 1007,
      severity_id: 4,
      src_ip: '10.0.0.5',
      dst_ip: null,
      hostname: 'WIN-DC01',
      username: 'svc-backup',
      process_hash: null,
      source: 'wazuh',
      summary: 'powershell.exe spawned by winword.exe',
    }),
  ),

  // Saved hunt queries
  http.get(`${BASE}/hunt/queries`, () =>
    HttpResponse.json({
      items: [
        {
          id: '92116ed0-eb10-4222-b47a-a08d8b56398c',
          name: 'Office spawning shells',
          description: null,
          query: 'powershell',
          filters: [],
          time_from: 'now-24h',
          time_to: 'now',
          created_by: 'hunter@mxtac.local',
          created_at: '2026-02-18T10:00:00+00:00',
          updated_at: '2026-02-18T10:00:00+00:00',
        },
      ],
      total: 1,
    }),
  ),

  http.post(`${BASE}/hunt/queries`, async ({ request }) => {
    const body = await request.json() as Record<string, unknown>
    return HttpResponse.json(
      {
        id: 'b48199ff-592d-4af1-813e-0e91dcc8b93f',
        name: body.name,
        description: body.description ?? null,
        query: body.query ?? null,
        filters: body.filters ?? [],
        time_from: body.time_from ?? 'now-24h',
        time_to: body.time_to ?? 'now',
        created_by: 'hunter@mxtac.local',
        created_at: '2026-02-19T09:00:00+00:00',
        updated_at: '2026-02-19T09:00:00+00:00',
      },
      { status: 201 },
    )
  }),

  http.put(`${BASE}/hunt/queries/:id`, async ({ params, request }) => {
    const body = await request.json() as Record<string, unknown>
    return HttpResponse.json({
      id: params.id,
      name: body.name ?? 'Office spawning shells',
      description: body.description ?? null,
      query: body.query ?? 'powershell',
      filters: body.filters ?? [],
      time_from: body.time_from ?? 'now-24h',
      time_to: body.time_to ?? 'now',
      created_by: 'hunter@mxtac.local',
      created_at: '2026-02-18T10:00:00+00:00',
      updated_at: '2026-02-19T09:00:00+00:00',
    })
  }),

  http.delete(`${BASE}/hunt/queries/:id`, () => new HttpResponse(null, { status: 204 })),

  // Coverage
  http.get(`${BASE}/coverage`, () =>
    HttpResponse.json({ coverage_pct: 40.0, covered_count: 42, total_count: 105 }),
  ),

  http.get(`${BASE}/coverage/gaps`, () =>
    HttpResponse.json({
      covered_count: 42,
      total_count: 105,
      gap_count: 63,
      coverage_pct: 40.0,
      uncovered_techniques: ['T1021.002', 'T1566.001'],
    }),
  ),

  http.get(`${BASE}/coverage/by-datasource`, () =>
    HttpResponse.json({
      sources: [
        { source: 'wazuh', covered_count: 30, total_count: 105, coverage_pct: 28.6, rule_count: 55 },
        { source: 'zeek', covered_count: 10, total_count: 105, coverage_pct: 9.5, rule_count: 12 },
        { source: 'suricata', covered_count: 0, total_count: 105, coverage_pct: 0.0, rule_count: 0 },
      ],
      total_covered_count: 38,
      total_count: 105,
      total_coverage_pct: 36.2,
    }),
  ),

  http.get(`${BASE}/coverage/navigator`, () =>
    HttpResponse.json({
      name: 'MxTac Coverage',
      versions: { attack: '14', navigator: '4.9', layer: '4.5' },
      domain: 'enterprise-attack',
      description: 'ATT&CK coverage exported from MxTac on 2026-02-19. Score = number of enabled Sigma rules covering the technique.',
      techniques: [
        {
          techniqueID: 'T1003.001',
          score: 4,
          color: '',
          comment: '4 rules covering this technique',
          enabled: true,
          metadata: [],
          links: [],
          showSubtechniques: false,
        },
      ],
    }),
  ),

  http.get(`${BASE}/coverage/trend`, ({ request }) => {
    const days = Number(new URL(request.url).searchParams.get('days') ?? 30)
    return HttpResponse.json({
      points: [
        { date: '2026-02-18', coverage_pct: 39.0, covered_count: 41, total_count: 105 },
        { date: '2026-02-19', coverage_pct: 40.0, covered_count: 42, total_count: 105 },
      ],
      days,
    })
  }),

  http.get(`${BASE}/coverage/target`, () =>
    HttpResponse.json({
      target_pct: 80.0,
      enabled: false,
      label: null,
      current_pct: 40.0,
      is_below_threshold: false,
    }),
  ),

  http.put(`${BASE}/coverage/target`, async ({ request }) => {
    const body = await request.json() as { target_pct: number; enabled?: boolean; label?: string | null }
    const enabled = body.enabled ?? true
    return HttpResponse.json({
      target_pct: body.target_pct,
      enabled,
      label: body.label ?? null,
      current_pct: 40.0,
      is_below_threshold: enabled && 40.0 < body.target_pct,
    })
  }),
]
