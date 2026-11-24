import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (file: string) => readFileSync(resolve(process.cwd(), file), 'utf8')

describe('frame protection of the application page', () => {
  it('does not put X-Frame-Options in a <meta> tag, which browsers ignore and report as a console error', () => {
    expect(read('index.html')).not.toMatch(/http-equiv=["']X-Frame-Options/i)
  })

  it('sends X-Frame-Options as a response header for the page in the production server', () => {
    const conf = read('nginx.conf')
    const pageLocation = conf.slice(conf.indexOf('location / {'))
    expect(pageLocation).toMatch(/add_header X-Frame-Options "DENY" always;/)
  })
})
