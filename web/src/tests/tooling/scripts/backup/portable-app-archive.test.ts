import { expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
    portableAppStateName,
    validateAppStateMember,
} from '../../../../../../scripts/backup/app-state.ts'
import { validateStateArchiveFile } from '../../../../../../scripts/backup/format.ts'
import { appendPortableAppState } from '../../../../../../scripts/backup/portable-app-archive.ts'
import type { BackupMetadata } from '../../../../../../scripts/backup/Types/format.types.ts'
import { portableAppState } from '@/tests/Helpers/portableAppStateFixture.ts'

function entry(name: string, body = Buffer.alloc(0), directory = false): Buffer {
    const header = Buffer.alloc(512)
    header.write(name)
    header.write(directory ? '0000700\0' : '0000600\0', 100)
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124)
    header.fill(32, 148, 156)
    header[156] = directory ? 53 : 48
    const checksum = header.reduce((sum, byte) => sum + byte, 0)
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148)
    return Buffer.concat([header, body, Buffer.alloc((512 - (body.length % 512)) % 512)])
}

// GNU tar pads the end-of-archive marker to its 10 KiB record.
function archive(...entries: Buffer[]): Buffer {
    const body = Buffer.concat(entries)
    return Buffer.concat([body, Buffer.alloc(10_240 - (body.length % 10_240))])
}

async function workspace() {
    const directory = await mkdtemp(join(tmpdir(), 'rp-portable-app-archive-'))
    const { snapshot, applications } = portableAppState()
    const state = join(directory, portableAppStateName)
    const controller = join(directory, 'controller-state.tar')
    await writeFile(state, snapshot)
    await writeFile(
        controller,
        archive(entry('./', undefined, true), entry('./routes.json', Buffer.from('{"routes":[]}'))),
    )
    return { directory, snapshot, applications, state, controller }
}

test('appends the captured app state as the single verified controller archive member', async () => {
    const { directory, snapshot, applications, state, controller } = await workspace()
    try {
        const result = await appendPortableAppState(controller, state, applications)
        const bytes = await readFile(controller)
        expect(result).toEqual({
            bytes: bytes.length,
            sha256: createHash('sha256').update(bytes).digest('hex'),
        })
        expect(bytes.length % 512).toBe(0)
        const file = await open(controller, 'r')
        try {
            const entries = await validateStateArchiveFile(file, 'controller')
            expect(entries.map(({ name }) => name)).toEqual([
                '',
                'routes.json',
                portableAppStateName,
            ])
            const metadata = { version: 6, applications } as unknown as BackupMetadata
            expect(await validateAppStateMember(file, entries, metadata)).toMatchObject({
                nodes: expect.any(Number),
                payloadBytes: expect.any(Number),
            })
        } finally {
            await file.close()
        }
        if (process.platform !== 'win32') {
            const extracted = join(directory, 'extracted')
            await mkdir(extracted)
            const tar = Bun.spawn(['tar', '-xf', controller, '-C', extracted], {
                stdout: 'ignore',
                stderr: 'pipe',
            })
            expect(await tar.exited, await new Response(tar.stderr).text()).toBe(0)
            expect(await readFile(join(extracted, portableAppStateName))).toEqual(snapshot)
        }
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('refuses a second app snapshot and a state that differs from its inspection', async () => {
    const { directory, applications, state, controller } = await workspace()
    try {
        const original = await readFile(controller)
        await expect(
            appendPortableAppState(controller, state, { ...applications, sha256: '0'.repeat(64) }),
        ).rejects.toThrow('Captured app state changed before archiving')
        await expect(
            appendPortableAppState(controller, state, {
                ...applications,
                bytes: applications.bytes + 1,
            }),
        ).rejects.toThrow('Invalid captured app state')

        await writeFile(
            controller,
            archive(
                entry('./', undefined, true),
                entry('./' + portableAppStateName, Buffer.from('stale')),
            ),
        )
        await expect(appendPortableAppState(controller, state, applications)).rejects.toThrow(
            'Controller state already contains an app snapshot',
        )

        await writeFile(controller, original.subarray(0, 512))
        await expect(appendPortableAppState(controller, state, applications)).rejects.toThrow()
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
