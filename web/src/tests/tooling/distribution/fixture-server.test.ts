import { expect, test } from 'bun:test'
import { link, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { serveFixture } from '../../../../../.github/scripts/ci/distribution/fixture-server.ts'

test('serves only repository files and supports package-manager range and HEAD requests', async () => {
    const root = await mkdtemp(join(tmpdir(), 'rp-distribution-http-'))
    try {
        const repository = 'repo-initial/apt'
        await mkdir(join(root, repository), { recursive: true })
        await writeFile(join(root, repository, 'package.deb'), '0123456789')
        await writeFile(join(root, 'fixture-fingerprint'), 'private fixture')
        await link(join(root, 'fixture-fingerprint'), join(root, repository, 'alias'))
        const server = await serveFixture(root, '127.0.0.1', 0)
        try {
            const packageUrl = new URL(repository + '/package.deb', server.url)
            const full = await fetch(packageUrl)
            expect(full.status).toBe(200)
            expect(await full.text()).toBe('0123456789')
            const head = await fetch(packageUrl, { method: 'HEAD' })
            expect(head.headers.get('Content-Length')).toBe('10')
            expect(await head.text()).toBe('')
            const partial = await fetch(packageUrl, { headers: { Range: 'bytes=2-5' } })
            expect(partial.status).toBe(206)
            expect(partial.headers.get('Content-Range')).toBe('bytes 2-5/10')
            expect(await partial.text()).toBe('2345')
            const suffix = await fetch(packageUrl, { headers: { Range: 'bytes=-2' } })
            expect(await suffix.text()).toBe('89')
            const invalid = await fetch(packageUrl, { headers: { Range: 'bytes=10-' } })
            expect(invalid.status).toBe(416)
            expect(invalid.headers.get('Content-Range')).toBe('bytes */10')
            expect((await fetch(packageUrl, { method: 'POST' })).status).toBe(405)
            const blocked = await Promise.all(
                [
                    repository,
                    repository + '/alias',
                    'fixture-fingerprint',
                    repository + '/%2Fetc',
                ].map((path) => fetch(new URL(path, server.url))),
            )
            expect(blocked.map(({ status }) => status)).toEqual([404, 404, 404, 404])
        } finally {
            await server.stop(true)
        }
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})
