import { describe, expect, test } from 'bun:test'
import { appCapabilitySchema, appIncidentChange } from '@/server/AppRuntime/contract.ts'

const open = {
    status: 'open',
    category: 'disk',
    severity: 'error',
    title: 'Disk almost full',
    message: 'The data volume has 2% left.',
}

const valid = (value: unknown) => appIncidentChange.safeParse(value).success

describe('the app incident change contract', () => {
    test('accepts open and resolved changes', () => {
        expect(valid(open)).toBeTrue()
        expect(valid({ ...open, resourceId: 'host-1' })).toBeTrue()
        expect(valid({ status: 'resolved' })).toBeTrue()
        for (const severity of ['warning', 'error', 'critical'])
            expect(valid({ ...open, severity })).toBeTrue()
    })

    test('refuses unknown fields, severities and states', () => {
        expect(valid({ status: 'resolved', category: 'disk' })).toBeFalse()
        expect(valid({ ...open, extra: true })).toBeFalse()
        expect(valid({ ...open, severity: 'info' })).toBeFalse()
        expect(valid({ ...open, status: 'closed' })).toBeFalse()
        expect(valid({ ...open, category: 'Not A Record' })).toBeFalse()
        expect(valid({ ...open, resourceId: 'Not A Record' })).toBeFalse()
        expect(valid({ status: 'open' })).toBeFalse()
    })

    test('bounds title and message by characters', () => {
        expect(valid({ ...open, title: 'x'.repeat(80) })).toBeTrue()
        expect(valid({ ...open, title: 'x'.repeat(81) })).toBeFalse()
        expect(valid({ ...open, title: '' })).toBeFalse()
        expect(valid({ ...open, message: 'm'.repeat(400) })).toBeTrue()
        expect(valid({ ...open, message: 'm'.repeat(401) })).toBeFalse()
        expect(valid({ ...open, message: '' })).toBeFalse()
        // Counted as characters, not UTF-16 units.
        expect(valid({ ...open, title: '\u{1F600}'.repeat(80) })).toBeTrue()
    })

    test('refuses control, surrogate, format and separator characters', () => {
        const texts = [
            'a\nb',
            'a\u0000b',
            'a\u007fb',
            'a‮b',
            'a​b',
            'a﻿b',
            'a\ud800b',
            'a b',
            'a b',
        ]
        for (const text of texts)
            for (const field of ['title', 'message'])
                expect(valid({ ...open, [field]: text })).toBeFalse()
    })

    test('refuses text that looks like a link', () => {
        const texts = [
            'see https://evil.example now',
            'HTTP://evil.example',
            'ftp://evil.example',
            'custom+scheme.v1://x',
            'visit www.evil.example',
            'WWW.EVIL.EXAMPLE',
            'mail mailto:someone@example.test',
            'MAILTO:x',
        ]
        for (const text of texts)
            for (const field of ['title', 'message'])
                expect(valid({ ...open, [field]: text })).toBeFalse()
        // Plain mentions of hosts and paths are not links.
        expect(valid({ ...open, message: 'service.example.test is down, see /var/log' })).toBeTrue()
        expect(valid({ ...open, message: 'Timeout: 30s' })).toBeTrue()
        // Like both contract SDKs, only ASCII letters fold case when looking for a scheme.
        expect(valid({ ...open, message: 'Marked \u017f://example.net as unreachable' })).toBeTrue()
    })

    test('the capability is an installation grant', () => {
        const id = 'notifications.incidents.manage.v1'
        expect(appCapabilitySchema.safeParse({ id, scope: 'installation' }).success).toBeTrue()
        for (const scope of ['proxyHosts', 'allProxyHosts', 'ownedProxyHosts'])
            expect(appCapabilitySchema.safeParse({ id, scope }).success).toBeFalse()
    })
})
