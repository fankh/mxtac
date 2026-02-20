// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RulesPage } from '../../components/features/rules/RulesPage'
import { apiClient } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references to the mocked API
// ---------------------------------------------------------------------------

const mockGet  = apiClient.get  as ReturnType<typeof vi.fn>
const mockPost = apiClient.post as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeRule = (overrides: Record<string, unknown> = {}) => ({
  id:           'rule-001',
  title:        'Suspicious LSASS Memory Access',
  level:        'high',
  status:       'experimental',
  enabled:      true,
  technique_ids: ['T1003.001'],
  tactic_ids:   ['credential_access'],
  hit_count:    42,
  fp_count:     2,
  ...overrides,
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        // Prevent background refetches that pollute call-count assertions.
        // Note: invalidateQueries() still forces a refetch even with staleTime:Infinity.
        staleTime: Infinity,
      },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <RulesPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Helper: open the YAML editor modal
// ---------------------------------------------------------------------------

async function openEditor() {
  fireEvent.click(await screen.findByRole('button', { name: '+ New Rule' }))
}

// ---------------------------------------------------------------------------
// Helper: get the YAML textarea element (distinct from the search input)
// ---------------------------------------------------------------------------

function getEditorTextarea(): HTMLTextAreaElement {
  return screen
    .getAllByRole('textbox')
    .find((el) => el.tagName.toLowerCase() === 'textarea') as HTMLTextAreaElement
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RulesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: pending forever → loading state
    mockGet.mockReturnValue(new Promise<never>(() => {}))
    mockPost.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading rules..." while the query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading rules...')).toBeInTheDocument()
    })

    it('does not show rule rows while loading', () => {
      renderPage()
      expect(screen.queryByText('Suspicious LSASS Memory Access')).not.toBeInTheDocument()
    })

    it('does not show the empty-state message while loading', () => {
      renderPage()
      expect(screen.queryByText('No rules loaded')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Success state — table rendering
  // =========================================================================
  describe('success state', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [makeRule()] })
    })

    it('renders the rule title', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Suspicious LSASS Memory Access')).toBeInTheDocument()
      })
    })

    it('renders the rule id as a sub-label', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('rule-001')).toBeInTheDocument()
      })
    })

    it('renders the rule level badge', async () => {
      renderPage()
      await waitFor(() => {
        // Level badge is a <span> inside the row; column header "Level" is also present
        expect(screen.getByText('high')).toBeInTheDocument()
      })
    })

    it('renders the rule status', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('experimental')).toBeInTheDocument()
      })
    })

    it('renders hit_count', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('42')).toBeInTheDocument()
      })
    })

    it('renders fp_count', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('2')).toBeInTheDocument()
      })
    })

    it('renders technique_ids', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('T1003.001')).toBeInTheDocument()
      })
    })

    it('shows "+{n}" overflow indicator when technique_ids exceed 2', async () => {
      mockGet.mockResolvedValue({
        data: [makeRule({ technique_ids: ['T1003.001', 'T1055', 'T1059'] })],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('+1')).toBeInTheDocument()
      })
    })

    it('renders multiple rule rows', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', title: 'Rule Alpha' }),
          makeRule({ id: 'r2', title: 'Rule Beta' }),
        ],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Rule Alpha')).toBeInTheDocument()
        expect(screen.getByText('Rule Beta')).toBeInTheDocument()
      })
    })

    it('does not show "Loading rules..." in success state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading rules...')).not.toBeInTheDocument()
      })
    })

    it('does not show the empty-state message when rules are present', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('No rules loaded')).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Empty state
  // =========================================================================
  describe('empty state', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('shows "No rules loaded" when the list is empty', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('No rules loaded')).toBeInTheDocument()
      })
    })

    it('shows "Create your first rule" link in empty state', async () => {
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Create your first rule')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Stats counter
  // =========================================================================
  describe('stats counter', () => {
    it('shows total and visible counts after data loads', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1' }),
          makeRule({ id: 'r2' }),
          makeRule({ id: 'r3' }),
        ],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('3 of 3 rules')).toBeInTheDocument()
      })
    })

    it('reflects filtered count after applying a level filter', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', level: 'high' }),
          makeRule({ id: 'r2', level: 'critical' }),
        ],
      })
      renderPage()
      await waitFor(() => expect(screen.getByText('2 of 2 rules')).toBeInTheDocument())

      fireEvent.click(screen.getByRole('button', { name: 'critical' }))
      await waitFor(() => {
        expect(screen.getByText('1 of 2 rules')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Column headers
  // =========================================================================
  describe('column headers', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders "Rule Title" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Rule Title')).toBeInTheDocument())
    })

    it('renders "Level" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Level')).toBeInTheDocument())
    })

    it('renders "Techniques" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Techniques')).toBeInTheDocument())
    })

    it('renders "Status" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Status')).toBeInTheDocument())
    })

    it('renders "Hits" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Hits')).toBeInTheDocument())
    })

    it('renders "FP" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('FP')).toBeInTheDocument())
    })

    it('renders "Active" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Active')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Filter bar — static rendering
  // =========================================================================
  describe('filter bar', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders the "critical" level filter button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'critical' })).toBeInTheDocument()
    })

    it('renders the "high" level filter button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'high' })).toBeInTheDocument()
    })

    it('renders the "medium" level filter button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'medium' })).toBeInTheDocument()
    })

    it('renders the "low" level filter button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'low' })).toBeInTheDocument()
    })

    it('renders the "Enabled only" filter button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Enabled only' })).toBeInTheDocument()
    })

    it('renders the search input', async () => {
      renderPage()
      expect(await screen.findByPlaceholderText('Search rules...')).toBeInTheDocument()
    })

    it('renders the "Import YAML" button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: 'Import YAML' })).toBeInTheDocument()
    })

    it('renders the "+ New Rule" button', async () => {
      renderPage()
      expect(await screen.findByRole('button', { name: '+ New Rule' })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Level filter — interaction
  // =========================================================================
  describe('level filter', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', title: 'Critical Rule', level: 'critical' }),
          makeRule({ id: 'r2', title: 'High Rule',     level: 'high' }),
          makeRule({ id: 'r3', title: 'Medium Rule',   level: 'medium' }),
        ],
      })
    })

    it('activates the level button when clicked (adds bg-blue class)', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'critical' })
      fireEvent.click(btn)
      expect(btn).toHaveClass('bg-blue')
    })

    it('deactivates the level button when clicked again (toggle off)', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'critical' })
      fireEvent.click(btn) // activate
      fireEvent.click(btn) // deactivate
      expect(btn).not.toHaveClass('bg-blue')
    })

    it('only one level button is active at a time', async () => {
      renderPage()
      const critBtn = await screen.findByRole('button', { name: 'critical' })
      const highBtn = screen.getByRole('button', { name: 'high' })
      fireEvent.click(critBtn)
      fireEvent.click(highBtn)
      expect(critBtn).not.toHaveClass('bg-blue')
      expect(highBtn).toHaveClass('bg-blue')
    })

    it('hides rules that do not match the selected level', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Critical Rule')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'critical' }))
      await waitFor(() => {
        expect(screen.getByText('Critical Rule')).toBeInTheDocument()
        expect(screen.queryByText('High Rule')).not.toBeInTheDocument()
        expect(screen.queryByText('Medium Rule')).not.toBeInTheDocument()
      })
    })

    it('shows all rules again when the active level filter is deactivated', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Critical Rule')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'critical' })) // activate
      fireEvent.click(screen.getByRole('button', { name: 'critical' })) // deactivate
      await waitFor(() => {
        expect(screen.getByText('Critical Rule')).toBeInTheDocument()
        expect(screen.getByText('High Rule')).toBeInTheDocument()
        expect(screen.getByText('Medium Rule')).toBeInTheDocument()
      })
    })

    it('does not trigger a new API call — filtering is client-side', async () => {
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByRole('button', { name: 'high' }))
      expect(mockGet).toHaveBeenCalledTimes(1)
    })
  })

  // =========================================================================
  // Enabled filter — interaction
  // =========================================================================
  describe('enabled filter', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', title: 'Enabled Rule',  enabled: true }),
          makeRule({ id: 'r2', title: 'Disabled Rule', enabled: false }),
        ],
      })
    })

    it('activates the "Enabled only" button when clicked', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Enabled only' })
      fireEvent.click(btn)
      expect(btn).toHaveClass('bg-blue')
    })

    it('deactivates the "Enabled only" button when clicked again', async () => {
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Enabled only' })
      fireEvent.click(btn)
      fireEvent.click(btn)
      expect(btn).not.toHaveClass('bg-blue')
    })

    it('hides disabled rules when "Enabled only" is active', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Disabled Rule')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'Enabled only' }))
      await waitFor(() => {
        expect(screen.getByText('Enabled Rule')).toBeInTheDocument()
        expect(screen.queryByText('Disabled Rule')).not.toBeInTheDocument()
      })
    })

    it('shows all rules again when "Enabled only" is deactivated', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Disabled Rule')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'Enabled only' })) // activate
      fireEvent.click(screen.getByRole('button', { name: 'Enabled only' })) // deactivate
      await waitFor(() => {
        expect(screen.getByText('Enabled Rule')).toBeInTheDocument()
        expect(screen.getByText('Disabled Rule')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Search — interaction
  // =========================================================================
  describe('search', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', title: 'LSASS Memory Dump' }),
          makeRule({ id: 'r2', title: 'PowerShell Execution' }),
        ],
      })
    })

    it('updates the input value as the user types', async () => {
      renderPage()
      const input = await screen.findByPlaceholderText('Search rules...')
      fireEvent.change(input, { target: { value: 'lsass' } })
      expect(input).toHaveValue('lsass')
    })

    it('hides rules whose title does not contain the search term', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('LSASS Memory Dump')).toBeInTheDocument())
      fireEvent.change(screen.getByPlaceholderText('Search rules...'), { target: { value: 'lsass' } })
      await waitFor(() => {
        expect(screen.getByText('LSASS Memory Dump')).toBeInTheDocument()
        expect(screen.queryByText('PowerShell Execution')).not.toBeInTheDocument()
      })
    })

    it('search is case-insensitive', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('PowerShell Execution')).toBeInTheDocument())
      fireEvent.change(screen.getByPlaceholderText('Search rules...'), { target: { value: 'POWERSHELL' } })
      await waitFor(() => {
        expect(screen.getByText('PowerShell Execution')).toBeInTheDocument()
        expect(screen.queryByText('LSASS Memory Dump')).not.toBeInTheDocument()
      })
    })

    it('shows all rules again when the search input is cleared', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('PowerShell Execution')).toBeInTheDocument())
      const input = screen.getByPlaceholderText('Search rules...')
      fireEvent.change(input, { target: { value: 'lsass' } })
      fireEvent.change(input, { target: { value: '' } })
      await waitFor(() => {
        expect(screen.getByText('LSASS Memory Dump')).toBeInTheDocument()
        expect(screen.getByText('PowerShell Execution')).toBeInTheDocument()
      })
    })

    it('does not trigger a new API call — filtering is client-side', async () => {
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
      fireEvent.change(await screen.findByPlaceholderText('Search rules...'), { target: { value: 'lsass' } })
      expect(mockGet).toHaveBeenCalledTimes(1)
    })
  })

  // =========================================================================
  // Combined filters
  // =========================================================================
  describe('combined filters', () => {
    it('applies level filter and search simultaneously', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeRule({ id: 'r1', title: 'Critical LSASS', level: 'critical' }),
          makeRule({ id: 'r2', title: 'High LSASS',     level: 'high' }),
          makeRule({ id: 'r3', title: 'Critical Other', level: 'critical' }),
        ],
      })
      renderPage()
      await waitFor(() => expect(screen.getByText('Critical LSASS')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'critical' }))
      fireEvent.change(screen.getByPlaceholderText('Search rules...'), { target: { value: 'lsass' } })
      await waitFor(() => {
        expect(screen.getByText('Critical LSASS')).toBeInTheDocument()
        expect(screen.queryByText('High LSASS')).not.toBeInTheDocument()
        expect(screen.queryByText('Critical Other')).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Editor modal — open and close
  // =========================================================================
  describe('editor modal', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('editor modal is not shown initially', async () => {
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalled())
      expect(screen.queryByText('New Sigma Rule')).not.toBeInTheDocument()
    })

    it('opens the editor when "+ New Rule" is clicked', async () => {
      renderPage()
      await openEditor()
      expect(screen.getByText('New Sigma Rule')).toBeInTheDocument()
    })

    it('shows a YAML textarea inside the modal', async () => {
      renderPage()
      await openEditor()
      expect(getEditorTextarea()).toBeInTheDocument()
    })

    it('pre-fills the textarea with the EXAMPLE_SIGMA template', async () => {
      renderPage()
      await openEditor()
      expect(getEditorTextarea().value).toContain('title: Suspicious LSASS Memory Access')
    })

    it('template contains all three required Sigma fields', async () => {
      renderPage()
      await openEditor()
      const value = getEditorTextarea().value
      expect(value).toContain('title:')
      expect(value).toContain('detection:')
      expect(value).toContain('logsource:')
    })

    it('shows the "Save Rule" button', async () => {
      renderPage()
      await openEditor()
      expect(screen.getByRole('button', { name: 'Save Rule' })).toBeInTheDocument()
    })

    it('shows the "Cancel" button', async () => {
      renderPage()
      await openEditor()
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    })

    it('shows the "Import file" button inside the modal', async () => {
      renderPage()
      await openEditor()
      expect(screen.getByRole('button', { name: 'Import file' })).toBeInTheDocument()
    })

    it('closes the modal when "Cancel" is clicked', async () => {
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByText('New Sigma Rule')).not.toBeInTheDocument()
    })

    it('closes the modal when the "x" button is clicked', async () => {
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'x' }))
      expect(screen.queryByText('New Sigma Rule')).not.toBeInTheDocument()
    })

    it('clicking "Create your first rule" link opens the editor', async () => {
      renderPage()
      const link = await screen.findByText('Create your first rule')
      fireEvent.click(link)
      expect(screen.getByText('New Sigma Rule')).toBeInTheDocument()
    })

    it('reopening the modal resets the YAML to the template', async () => {
      renderPage()
      await openEditor()
      // Modify the textarea
      fireEvent.change(getEditorTextarea(), { target: { value: 'modified content' } })
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      // Reopen
      fireEvent.click(screen.getByRole('button', { name: '+ New Rule' }))
      expect(getEditorTextarea().value).toContain('title: Suspicious LSASS Memory Access')
    })

    it('reopening the modal clears any previous validation errors', async () => {
      renderPage()
      await openEditor()
      fireEvent.change(getEditorTextarea(), { target: { value: '' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('YAML content is empty')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      fireEvent.click(screen.getByRole('button', { name: '+ New Rule' }))
      expect(screen.queryByText('YAML content is empty')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // YAML validation
  // =========================================================================
  describe('YAML validation', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    async function openModalWithYaml(yaml: string) {
      await openEditor()
      fireEvent.change(getEditorTextarea(), { target: { value: yaml } })
    }

    it('shows "YAML content is empty" when the textarea is blank', async () => {
      renderPage()
      await openModalWithYaml('')
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('YAML content is empty')).toBeInTheDocument()
    })

    it('shows "YAML content is empty" for whitespace-only content', async () => {
      renderPage()
      await openModalWithYaml('   \n  ')
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('YAML content is empty')).toBeInTheDocument()
    })

    it('shows missing "title" error when the title field is absent', async () => {
      renderPage()
      await openModalWithYaml(
        'detection:\n  selection:\n    x: y\n  condition: selection\nlogsource:\n  product: windows\n',
      )
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('Missing required field: "title"')).toBeInTheDocument()
    })

    it('shows missing "detection" error when the detection field is absent', async () => {
      renderPage()
      await openModalWithYaml('title: My Rule\nlogsource:\n  product: windows\n')
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('Missing required field: "detection"')).toBeInTheDocument()
    })

    it('shows missing "logsource" error when the logsource field is absent', async () => {
      renderPage()
      await openModalWithYaml(
        'title: My Rule\ndetection:\n  selection:\n    x: y\n  condition: selection\n',
      )
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('Missing required field: "logsource"')).toBeInTheDocument()
    })

    it('shows multiple missing-field errors simultaneously', async () => {
      renderPage()
      await openModalWithYaml('title: My Rule\n')
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('Missing required field: "detection"')).toBeInTheDocument()
      expect(screen.getByText('Missing required field: "logsource"')).toBeInTheDocument()
    })

    it('does not call apiClient.post when validation fails', async () => {
      renderPage()
      await openModalWithYaml('')
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(mockPost).not.toHaveBeenCalled()
    })

    it('clears validation errors as the user types in the textarea', async () => {
      renderPage()
      await openEditor()
      fireEvent.change(getEditorTextarea(), { target: { value: '' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('YAML content is empty')).toBeInTheDocument()
      // Type to clear
      fireEvent.change(getEditorTextarea(), { target: { value: 'title: x' } })
      expect(screen.queryByText('YAML content is empty')).not.toBeInTheDocument()
    })

    it('does not show validation errors for valid YAML (all required fields present)', async () => {
      mockPost.mockResolvedValue({ data: { id: 'new-rule' } })
      renderPage()
      await openEditor()
      // EXAMPLE_SIGMA is pre-filled and valid — click Save directly
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(screen.queryByText('YAML content is empty')).not.toBeInTheDocument()
        expect(screen.queryByText(/Missing required field/)).not.toBeInTheDocument()
      })
    })

    it('ignores indented lines (does not treat nested keys as top-level)', async () => {
      // YAML with all top-level keys present — nested "detection" inside a comment block
      // should not satisfy the top-level "detection" requirement
      renderPage()
      await openModalWithYaml(
        'title: My Rule\nlogsource:\n  product: windows\n  # detection: nested\n',
      )
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(screen.getByText('Missing required field: "detection"')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Save mutation — success
  // =========================================================================
  describe('save mutation — success', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
      mockPost.mockResolvedValue({
        data: { id: 'new-rule-id', title: 'Suspicious LSASS Memory Access' },
      })
    })

    it('calls apiClient.post with the correct endpoint and payload', async () => {
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(mockPost).toHaveBeenCalledWith(
          '/rules',
          expect.objectContaining({
            title:   'Suspicious LSASS Memory Access',
            content: expect.stringContaining('title: Suspicious LSASS Memory Access'),
            enabled: true,
          }),
        )
      })
    })

    it('closes the modal on successful save', async () => {
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(screen.queryByText('New Sigma Rule')).not.toBeInTheDocument()
      })
    })

    it('invalidates the rules query — triggers a refetch after save', async () => {
      mockGet
        .mockResolvedValueOnce({ data: [] })
        .mockResolvedValue({ data: [makeRule()] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
    })

    it('shows "Saving..." label while the mutation is in-flight', async () => {
      let resolve: (v: unknown) => void
      mockPost.mockReturnValue(new Promise((r) => { resolve = r }))
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      expect(await screen.findByRole('button', { name: 'Saving...' })).toBeInTheDocument()
      resolve!({ data: {} })
    })

    it('disables the Save button while saving', async () => {
      let resolve: (v: unknown) => void
      mockPost.mockReturnValue(new Promise((r) => { resolve = r }))
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      const savingBtn = await screen.findByRole('button', { name: 'Saving...' })
      expect(savingBtn).toBeDisabled()
      resolve!({ data: {} })
    })

    it('extracts the title from the YAML for the API payload', async () => {
      renderPage()
      await openEditor()
      fireEvent.change(getEditorTextarea(), {
        target: {
          value:
            'title: My Custom Rule\ndetection:\n  selection:\n    x: y\n  condition: selection\nlogsource:\n  product: linux\n',
        },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(mockPost).toHaveBeenCalledWith(
          '/rules',
          expect.objectContaining({ title: 'My Custom Rule' }),
        )
      })
    })

    it('falls back to "Untitled Rule" when the title value is empty', async () => {
      renderPage()
      await openEditor()
      // "title:" with no value passes validation but has no extractable title
      const emptyTitleYaml =
        'title:\ndetection:\n  selection:\n    x: y\n  condition: selection\nlogsource:\n  product: linux\n'
      fireEvent.change(getEditorTextarea(), { target: { value: emptyTitleYaml } })
      // Confirm the state update took effect before clicking Save
      await waitFor(() => expect(getEditorTextarea().value).toBe(emptyTitleYaml))
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      // Wait for the API to be called (any args), then verify the title fallback
      await waitFor(() => expect(mockPost).toHaveBeenCalled())
      const [endpoint, payload] = mockPost.mock.calls[0] as [string, Record<string, unknown>]
      expect(endpoint).toBe('/rules')
      expect(payload.title).toBe('Untitled Rule')
    })
  })

  // =========================================================================
  // Save mutation — error
  // =========================================================================
  describe('save mutation — error', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('shows the API error detail when save fails with a structured error', async () => {
      mockPost.mockRejectedValue({
        response: { data: { detail: 'Invalid Sigma YAML syntax' } },
      })
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(screen.getByText('Invalid Sigma YAML syntax')).toBeInTheDocument()
      })
    })

    it('shows "Failed to save rule" fallback when the error has no detail field', async () => {
      mockPost.mockRejectedValue(new Error('Network error'))
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(screen.getByText('Failed to save rule')).toBeInTheDocument()
      })
    })

    it('keeps the modal open when save fails', async () => {
      mockPost.mockRejectedValue(new Error('fail'))
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => {
        expect(screen.getByText('Failed to save rule')).toBeInTheDocument()
        expect(screen.getByText('New Sigma Rule')).toBeInTheDocument()
      })
    })

    it('clears the API error when the user types in the textarea', async () => {
      mockPost.mockRejectedValue(new Error('fail'))
      renderPage()
      await openEditor()
      fireEvent.click(screen.getByRole('button', { name: 'Save Rule' }))
      await waitFor(() => expect(screen.getByText('Failed to save rule')).toBeInTheDocument())
      fireEvent.change(getEditorTextarea(), { target: { value: 'new content' } })
      expect(screen.queryByText('Failed to save rule')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with the "Sigma Rules" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Sigma Rules')
    })
  })
})
