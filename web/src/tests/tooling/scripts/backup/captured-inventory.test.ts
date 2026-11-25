import { expect, test } from 'bun:test'
import {
    decodeCapturedInstallations,
    encodeCapturedInstallations,
} from '../../../../../../scripts/backup/captured-inventory.ts'
import {
    portableAppCaptureCommand,
    postgresDumpCommand,
} from '../../../../../../scripts/backup/volume-commands.ts'
import { portableInstallation } from '@/tests/Helpers/portableAppStateFixture.ts'

test('passes only a valid captured inventory to the offline database check', () => {
    const installations = [portableInstallation, { ...portableInstallation, id: 'kiri-2', uid: 20001 }]
    const encoded = encodeCapturedInstallations(installations)
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/u)
    expect(decodeCapturedInstallations(encoded)).toEqual(installations)

    // Every installation may carry the longest identities the schema allows.
    const largest = Array.from({ length: 256 }, (_, index) => ({
        id: 'a' + String(index).padStart(63, '0'),
        appId: 'b'.repeat(98),
        uid: 20000 + index,
        generation: Number.MAX_SAFE_INTEGER,
        authorityRecorded: false,
    }))
    expect(decodeCapturedInstallations(encodeCapturedInstallations(largest))).toEqual(largest)

    expect(() => encodeCapturedInstallations([])).toThrow()
    expect(() => encodeCapturedInstallations([{ ...portableInstallation, uid: 1 }])).toThrow()
    for (const value of [
        '',
        'not base64!',
        encoded.slice(0, -1),
        'A'.repeat(96 * 1024 + 4),
        Buffer.from('[]').toString('base64'),
        Buffer.from('{"id":"kiri-1"}').toString('base64'),
        Buffer.from([0xff, 0xfe, 0xfd]).toString('base64'),
    ])
        expect(() => decodeCapturedInstallations(value)).toThrow()
})

test('checks the main database against the captured inventory instead of refusing apps', () => {
    const legacy = postgresDumpCommand()
    expect(legacy).toContain('--app-backup empty')
    expect(legacy).toContain("rolname ~ '^rp_(app|migrate)_[0-9]+$'")
    expect(legacy).not.toContain('--check-live-app-inventory')

    const encoded = encodeCapturedInstallations([portableInstallation])
    const portable = postgresDumpCommand([portableInstallation])
    expect(portable).not.toContain('--app-backup empty')
    expect(portable).not.toContain("rolname ~ '^rp_(app|migrate)_[0-9]+$'")
    expect(portable).toContain(
        'bun --no-env-file /opt/rentnerproxy/web/backup-export.js --check-live-app-inventory ' +
            encoded +
            '\ngosu postgres pg_dump ',
    )
    for (const command of [legacy, portable]) {
        expect(command.indexOf('"$ready"')).toBeLessThan(command.indexOf('pg_dump --host'))
        expect(command).toContain('trap cleanup EXIT')
    }
})

test('captures app state only from app storage with the cluster running', () => {
    const command = portableAppCaptureCommand()
    const exit = command.indexOf('|| exit 0')
    expect(command).toContain('/var/lib/rentnerproxy/apps /var/lib/rentnerproxy/app-manager')
    expect(exit).toBeGreaterThan(0)
    expect(exit).toBeLessThan(command.indexOf('gosu postgres postgres -D'))
    expect(command.indexOf('"$ready"')).toBeLessThan(command.indexOf('capture-portable'))
    expect(command.endsWith('/usr/local/bin/rentnerproxy-controller --app-backup capture-portable')).toBe(
        true,
    )
    expect(command).not.toContain('pg_dump')
})
