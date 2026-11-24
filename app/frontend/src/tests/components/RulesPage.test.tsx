// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof ApiModule>()
  return {
    ...actual,
    rulesApi: {
      list: vi.fn(),
      stats: vi.fn(),
      get: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      import: vi.fn(),
      reload: vi.fn(),
      testContent: vi.fn(),
      test: vi.fn(),
      markFalsePositive: vi.fn(),
    },
  }
})

// The real TopBar opens the alert WebSocket; the page frame only needs its slots.
vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header>
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

// Monaco does not run in jsdom: a textarea stands in for the YAML editor.
vi.mock('@monaco-editor/react', () => ({
  default: ({ value, onChange, theme, options }: {
    value?: string
    onChange?: (value: string | undefined) => void
    theme?: string
    options?: { readOnly?: boolean }
  }) => (
    <textarea
      aria-label="Rule YAML"
      data-theme={theme}
      readOnly={options?.readOnly}
      value={value ?? ''}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}))

import type { ReactNode } from 'react'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RulesPage } from '../../components/features/rules/RulesPage'
import type * as ApiModule from '../../lib/api'
import { rulesApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type { Rule, RuleDetail } from '../../types/api'
import { chooseOption } from '../mocks/radixSelect'

const api = vi.mocked(rulesApi)

function makeRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'rule-lsass',
    title: 'Suspicious LSASS memory access',
    level: 'high',
    status: 'experimental',
    enabled: true,
    technique_ids: ['T1003.001'],
    tactic_ids: ['credential_access'],
    logsource: { product: 'windows', category: 'process_access' },
    hit_count: 42,
    fp_count: 2,
    ...overrides,
  }
}

const RULES: Rule[] = [
  makeRule(),
  makeRule({
    id: 'rule-ps',
    title: 'Encoded PowerShell command',
    level: 'critical',
    enabled: false,
    technique_ids: ['T1059.001', 'T1027', 'T1140'],
    logsource: {},
    hit_count: 0,
    fp_count: 0,
  }),
]

const STORED_YAML = 'title: Suspicious LSASS memory access\ndetection:\n  selection:\n    EventID: 10\n  condition: selection\nlevel: high\n'

const DETAIL: RuleDetail = { ...RULES[0], content: STORED_YAML, description: '', source: 'custom', created_by: null }

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <RulesPage />
    </QueryClientProvider>,
  )
}

async function renderLoaded() {
  const view = renderPage()
  await screen.findByText('Suspicious LSASS memory access')
  return view
}

function setRole(role: string) {
  useAuthStore.setState({ user: { email: 'user@mxtac.local', role } })
}

function notifications() {
  return useUIStore.getState().notifications
}

function yamlEditor(): HTMLTextAreaElement {
  return screen.getByLabelText('Rule YAML') as HTMLTextAreaElement
}

beforeEach(() => {
  vi.clearAllMocks()
  useUIStore.setState({ notifications: [], theme: 'dark' })
  setRole('engineer')
  api.list.mockResolvedValue(RULES)
  api.stats.mockResolvedValue({ total: 2, enabled: 1, by_level: { high: 1, critical: 1 } })
  api.get.mockResolvedValue(DETAIL)
})

describe('RulesPage', () => {
  describe('list', () => {
    it('shows a loading skeleton while rules load', () => {
      api.list.mockReturnValue(new Promise<Rule[]>(() => {}))
      renderPage()
      expect(screen.getByLabelText('Loading rules')).toBeInTheDocument()
      expect(screen.queryByText('No rules yet')).not.toBeInTheDocument()
    })

    it('lists rules with level, techniques, log source and counters', async () => {
      await renderLoaded()
      const row = screen.getByText('Suspicious LSASS memory access').closest('tr') as HTMLElement
      expect(within(row).getByText('rule-lsass')).toBeInTheDocument()
      expect(within(row).getByText('high')).toBeInTheDocument()
      expect(within(row).getByText('T1003.001')).toBeInTheDocument()
      expect(within(row).getByText('windows / process_access')).toBeInTheDocument()
      expect(within(row).getByText('42')).toBeInTheDocument()
    })

    it('names the techniques in the tooltips of the technique tags', async () => {
      await renderLoaded()
      const row = screen.getByText('Encoded PowerShell command').closest('tr') as HTMLElement
      // From GET /attack/techniques (MSW handler); T1027 is not in the test table
      await waitFor(() =>
        expect(within(row).getByText('T1059.001')).toHaveAttribute('title', 'Command and Scripting Interpreter: PowerShell'))
      expect(within(row).getByText('T1027')).not.toHaveAttribute('title')
    })

    it('shows two techniques and a count for the rest', async () => {
      await renderLoaded()
      const row = screen.getByText('Encoded PowerShell command').closest('tr') as HTMLElement
      expect(within(row).getByText('T1059.001')).toBeInTheDocument()
      expect(within(row).getByText('T1027')).toBeInTheDocument()
      expect(within(row).queryByText('T1140')).not.toBeInTheDocument()
      expect(within(row).getByText('+1')).toBeInTheDocument()
    })

    it('shows totals from GET /rules/stats/summary', async () => {
      await renderLoaded()
      const card = (label: string) => screen.getByText(label, { selector: 'p' }).parentElement as HTMLElement
      await waitFor(() => expect(within(card('Rules')).getByText('2')).toBeInTheDocument())
      expect(within(card('Enabled')).getByText('1')).toBeInTheDocument()
      expect(within(card('Critical')).getByText('1')).toBeInTheDocument()
    })

    it('shows an empty state with a create action when there are no rules', async () => {
      api.list.mockResolvedValue([])
      renderPage()
      expect(await screen.findByText('No rules yet')).toBeInTheDocument()
    })

    it('shows an error with Retry when the request fails, and reloads on Retry', async () => {
      api.list.mockRejectedValueOnce(new Error('boom'))
      renderPage()
      expect(await screen.findByText('Could not load rules.')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
      expect(await screen.findByText('Suspicious LSASS memory access')).toBeInTheDocument()
      expect(api.list).toHaveBeenCalledTimes(2)
    })
  })

  describe('search and filters', () => {
    it('filters by title, and by technique ID', async () => {
      await renderLoaded()
      const search = screen.getByLabelText('Search rules')
      fireEvent.change(search, { target: { value: 'powershell' } })
      expect(screen.queryByText('Suspicious LSASS memory access')).not.toBeInTheDocument()
      expect(screen.getByText('Encoded PowerShell command')).toBeInTheDocument()
      expect(screen.getByText('1 of 2 rules')).toBeInTheDocument()

      fireEvent.change(search, { target: { value: 't1003' } })
      expect(screen.getByText('Suspicious LSASS memory access')).toBeInTheDocument()
      expect(screen.queryByText('Encoded PowerShell command')).not.toBeInTheDocument()
    })

    it('clears the search with the clear button and with Escape', async () => {
      await renderLoaded()
      const search = screen.getByLabelText('Search rules') as HTMLInputElement
      fireEvent.change(search, { target: { value: 'zzz' } })
      expect(screen.getByText('No rules match')).toBeInTheDocument()
      fireEvent.click(screen.getByTitle('Clear search'))
      expect(search.value).toBe('')

      fireEvent.change(search, { target: { value: 'zzz' } })
      fireEvent.keyDown(search, { key: 'Escape' })
      expect(search.value).toBe('')
      expect(screen.getByText('Encoded PowerShell command')).toBeInTheDocument()
    })

    it('filters by level', async () => {
      await renderLoaded()
      await chooseOption('Level', 'critical')
      await waitFor(() => expect(screen.queryByText('Suspicious LSASS memory access')).not.toBeInTheDocument())
      expect(screen.getByText('Encoded PowerShell command')).toBeInTheDocument()
    })

    it('filters by enabled state', async () => {
      await renderLoaded()
      await chooseOption('State', 'Enabled')
      await waitFor(() => expect(screen.queryByText('Encoded PowerShell command')).not.toBeInTheDocument())
      expect(screen.getByText('Suspicious LSASS memory access')).toBeInTheDocument()
    })
  })

  describe('row actions', () => {
    it('disables a rule through PATCH /rules/{id}', async () => {
      api.update.mockResolvedValue(makeRule({ enabled: false }))
      await renderLoaded()
      fireEvent.click(screen.getByRole('switch', { name: 'Disable Suspicious LSASS memory access' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith('rule-lsass', { enabled: false }))
    })

    it('reports a failed toggle', async () => {
      api.update.mockRejectedValue({ response: { data: { detail: 'Rule not found' } } })
      await renderLoaded()
      fireEvent.click(screen.getByRole('switch', { name: 'Enable Encoded PowerShell command' }))
      await waitFor(() => expect(notifications()).toHaveLength(1))
      expect(notifications()[0]).toMatchObject({ type: 'error', message: 'Rule not found' })
    })

    it('deletes a rule after confirmation', async () => {
      api.delete.mockResolvedValue(undefined)
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Delete Suspicious LSASS memory access'))
      expect(api.delete).not.toHaveBeenCalled()
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith('rule-lsass'))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    })

    it('keeps the rule when the delete dialog is cancelled', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Delete Suspicious LSASS memory access'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(api.delete).not.toHaveBeenCalled()
    })

    it('records a false positive through POST /rules/{id}/mark_fp', async () => {
      api.markFalsePositive.mockResolvedValue({ rule_id: 'rule-lsass', status: 'marked' })
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Mark a false positive for Suspicious LSASS memory access'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Mark false positive' }))
      await waitFor(() => expect(api.markFalsePositive).toHaveBeenCalledWith('rule-lsass'))
      await waitFor(() => expect(notifications()[0]).toMatchObject({ type: 'success' }))
    })

    it('tests a stored rule against a sample event', async () => {
      api.test.mockResolvedValue({ matched: false, errors: [] })
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Test Suspicious LSASS memory access'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('Sample event (JSON)'), { target: { value: '{"EventID": 10}' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Run test' }))
      await waitFor(() => expect(api.test).toHaveBeenCalledWith('rule-lsass', { EventID: 10 }))
      expect(await within(dialog).findByText('No match')).toBeInTheDocument()
    })
  })

  describe('engine reload and import', () => {
    it('reloads the detection engine', async () => {
      api.reload.mockResolvedValue({ reloaded: 2, total_rules: 2 })
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Reload engine' }))
      await waitFor(() => expect(api.reload).toHaveBeenCalledTimes(1))
      await waitFor(() => expect(notifications()[0]).toMatchObject({ type: 'success', message: '2 of 2 rules loaded' }))
    })

    it('imports pasted YAML through POST /rules/import', async () => {
      api.import.mockResolvedValue({ imported: 2, total_rules: 4 })
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Import' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('YAML'), { target: { value: `${STORED_YAML}---\n${STORED_YAML}` } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }))
      await waitFor(() => expect(api.import).toHaveBeenCalledWith(`${STORED_YAML}---\n${STORED_YAML}`))
      await waitFor(() => expect(notifications()[0]).toMatchObject({ type: 'success', title: 'Imported 2 rules' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    })

    it('does not send an empty import', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Import' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }))
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Paste Sigma YAML or choose a file first.')
      expect(api.import).not.toHaveBeenCalled()
    })

    it('keeps the dialog open when nothing was imported', async () => {
      api.import.mockResolvedValue({ imported: 0, total_rules: 2 })
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Import' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('YAML'), { target: { value: 'not: a rule' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }))
      expect(await within(dialog).findByText('No valid Sigma rules were found in this YAML.')).toBeInTheDocument()
    })

    it('shows why each skipped rule was refused and keeps the dialog open', async () => {
      api.import.mockResolvedValue({
        imported: 1,
        total_rules: 3,
        errors: ["Too Many Logins: aggregation expressions ('| count() ...', '| near ...') are not supported"],
      })
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Import' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('YAML'), { target: { value: `${STORED_YAML}---
${STORED_YAML}` } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }))

      const alert = await within(dialog).findByRole('alert')
      expect(alert).toHaveTextContent('Imported 1 rule. Skipped 1:')
      expect(alert).toHaveTextContent('Too Many Logins: aggregation expressions')
      expect(notifications()[0]).toMatchObject({ type: 'warning', title: 'Imported 1 rule' })
      // The imported rule shows in the list behind the dialog; the dialog is left with Done.
      expect(within(dialog).getByRole('button', { name: 'Done' })).toBeInTheDocument()
      expect(within(dialog).queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
    })

    it('shows the reasons when every rule was refused', async () => {
      api.import.mockResolvedValue({ imported: 0, total_rules: 2, errors: ["Only Title: rule has no 'detection' section"] })
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Import' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('YAML'), { target: { value: 'title: Only Title' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Import' }))

      const alert = await within(dialog).findByRole('alert')
      expect(alert).toHaveTextContent('Nothing was imported. Skipped 1:')
      expect(alert).toHaveTextContent("Only Title: rule has no 'detection' section")
      expect(within(dialog).queryByText('No valid Sigma rules were found in this YAML.')).not.toBeInTheDocument()
    })
  })

  describe('editor', () => {
    async function openNewRule() {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'New rule' }))
      return screen.findByRole('dialog')
    }

    it('opens with an example rule and creates it with the title from the YAML', async () => {
      api.create.mockResolvedValue(makeRule({ id: 'rule-new' }))
      const dialog = await openNewRule()
      const content = yamlEditor().value
      expect(content).toContain('title: Suspicious LSASS memory access')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
      expect(api.create).toHaveBeenCalledWith({ title: 'Suspicious LSASS memory access', content, enabled: true })
    })

    it('creates a disabled rule when "Enable after saving" is off', async () => {
      api.create.mockResolvedValue(makeRule({ id: 'rule-new', enabled: false }))
      const dialog = await openNewRule()
      fireEvent.click(within(dialog).getByRole('switch', { name: 'Enable after saving' }))
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledWith(expect.objectContaining({ enabled: false })))
    })

    it('blocks saving a rule without a detection block', async () => {
      const dialog = await openNewRule()
      fireEvent.change(yamlEditor(), { target: { value: 'title: Only a title\nlevel: low\n' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
      expect(within(dialog).getByText('Missing required field: detection')).toBeInTheDocument()
      expect(api.create).not.toHaveBeenCalled()
    })

    it('blocks saving invalid YAML and names the line', async () => {
      const dialog = await openNewRule()
      fireEvent.change(yamlEditor(), { target: { value: 'title: Broken\ndetection: [unclosed\n' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
      expect(within(dialog).getByRole('alert')).toHaveTextContent(/YAML syntax error \(line \d+\)/)
      expect(api.create).not.toHaveBeenCalled()
    })

    it('shows the server message when saving fails', async () => {
      api.create.mockRejectedValue({ response: { data: { detail: 'Invalid Sigma YAML' } } })
      const dialog = await openNewRule()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
      expect(await within(dialog).findByText('Invalid Sigma YAML')).toBeInTheDocument()
      expect(notifications()[0]).toMatchObject({ type: 'error', title: 'Save failed' })
    })

    it('loads a stored rule and saves the edited YAML with PATCH', async () => {
      api.update.mockResolvedValue(RULES[0])
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Suspicious LSASS memory access' }))
      const dialog = await screen.findByRole('dialog')
      await waitFor(() => expect(yamlEditor().value).toBe(STORED_YAML))
      expect(api.get).toHaveBeenCalledWith('rule-lsass')

      const edited = STORED_YAML.replace('level: high', 'level: critical')
      fireEvent.change(yamlEditor(), { target: { value: edited } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save rule' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith('rule-lsass', { content: edited }))
    })

    it('offers Retry when the stored rule cannot be loaded', async () => {
      api.get.mockRejectedValueOnce(new Error('boom'))
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Edit Suspicious LSASS memory access'))
      const dialog = await screen.findByRole('dialog')
      expect(await within(dialog).findByText('Could not load this rule.')).toBeInTheDocument()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Retry' }))
      await waitFor(() => expect(yamlEditor().value).toBe(STORED_YAML))
    })

    it('tests unsaved YAML against the sample event', async () => {
      api.testContent.mockResolvedValue({ matched: true, errors: [] })
      const dialog = await openNewRule()
      fireEvent.change(within(dialog).getByLabelText('Sample event (JSON)'), { target: { value: '{"GrantedAccess": "0x1010"}' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Run test' }))
      await waitFor(() => expect(api.testContent).toHaveBeenCalledWith(yamlEditor().value, { GrantedAccess: '0x1010' }))
      expect(await within(dialog).findByText('Matched')).toBeInTheDocument()
    })

    it('shows rule errors returned by the test endpoint', async () => {
      api.testContent.mockResolvedValue({ matched: false, errors: ["'detection' block is missing 'condition'"] })
      const dialog = await openNewRule()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Run test' }))
      expect(await within(dialog).findByText('Rule error')).toBeInTheDocument()
      expect(within(dialog).getByText("'detection' block is missing 'condition'")).toBeInTheDocument()
    })

    it('rejects a sample event that is not a JSON object', async () => {
      const dialog = await openNewRule()
      const sample = within(dialog).getByLabelText('Sample event (JSON)')
      fireEvent.change(sample, { target: { value: '{not json' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Run test' }))
      expect(within(dialog).getByText('The sample event is not valid JSON')).toBeInTheDocument()

      fireEvent.change(sample, { target: { value: '[1, 2]' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Run test' }))
      expect(within(dialog).getByText('The sample event must be a JSON object')).toBeInTheDocument()
      expect(api.testContent).not.toHaveBeenCalled()
    })

    it('re-indents the YAML with Format', async () => {
      const dialog = await openNewRule()
      fireEvent.change(yamlEditor(), { target: { value: 'title:    Spaced\ndetection:\n      condition:   selection\n' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Format' }))
      expect(yamlEditor().value).toBe('title: Spaced\ndetection:\n  condition: selection\n')
    })

    it('uses the Monaco theme that matches the app theme', async () => {
      useUIStore.setState({ theme: 'light' })
      await openNewRule()
      expect(yamlEditor()).toHaveAttribute('data-theme', 'vs')
    })

    it('uses the dark Monaco theme in dark mode', async () => {
      await openNewRule()
      expect(yamlEditor()).toHaveAttribute('data-theme', 'vs-dark')
    })
  })

  describe('read-only role', () => {
    beforeEach(() => setRole('hunter'))

    it('hides create, import, reload, edit and delete for a hunter', async () => {
      await renderLoaded()
      expect(screen.queryByRole('button', { name: 'New rule' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Import' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Reload engine' })).not.toBeInTheDocument()
      expect(screen.queryByTitle('Delete Suspicious LSASS memory access')).not.toBeInTheDocument()
      expect(screen.queryByTitle('Edit Suspicious LSASS memory access')).not.toBeInTheDocument()
      expect(screen.getByRole('switch', { name: 'Disable Suspicious LSASS memory access' })).toBeDisabled()
    })

    it('opens a rule read-only, still testable', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Suspicious LSASS memory access' }))
      const dialog = await screen.findByRole('dialog')
      await waitFor(() => expect(yamlEditor().value).toBe(STORED_YAML))
      expect(yamlEditor()).toHaveAttribute('readonly')
      expect(within(dialog).queryByRole('button', { name: 'Save rule' })).not.toBeInTheDocument()
      expect(within(dialog).getByRole('button', { name: 'Run test' })).toBeInTheDocument()
    })
  })
})
