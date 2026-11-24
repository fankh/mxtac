// Minimal ambient declarations for the parts of js-yaml (v4) this app uses.
// The package ships no types and @types/js-yaml is not installed.
declare module 'js-yaml' {
  export interface Mark {
    name: string | null
    buffer: string
    position: number
    line: number
    column: number
    snippet?: string
  }

  export class YAMLException extends Error {
    constructor(reason?: string, mark?: Mark)
    reason: string
    mark?: Mark
    toString(compact?: boolean): string
  }

  export interface LoadOptions {
    filename?: string
    json?: boolean
  }

  export interface DumpOptions {
    indent?: number
    lineWidth?: number
    noRefs?: boolean
    sortKeys?: boolean
    quotingType?: "'" | '"'
    forceQuotes?: boolean
  }

  export function load(input: string, options?: LoadOptions): unknown
  export function loadAll(input: string, iterator?: null, options?: LoadOptions): unknown[]
  export function dump(input: unknown, options?: DumpOptions): string
}
