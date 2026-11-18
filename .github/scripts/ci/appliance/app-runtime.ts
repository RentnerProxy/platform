import { fileURLToPath } from 'node:url'
import type { ApplianceManagementAndPersistenceContext } from './Types/scenarios.types.ts'

export async function verifyApplianceAppRuntime(context: ApplianceManagementAndPersistenceContext) {
    const source = fileURLToPath(new URL('../fixtures/production-app-runtime.ts', import.meta.url))
    const target = '/usr/local/lib/rentnerproxy-app-runtime-fixture.ts'
    await context.command([...context.compose, 'cp', source, 'rentnerproxy:' + target])
    try {
        await context.command([
            ...context.compose,
            'exec',
            '-T',
            'rentnerproxy',
            'chmod',
            '0555',
            target,
        ])
        await context.command(
            [
                ...context.compose,
                'exec',
                '-T',
                'rentnerproxy',
                'timeout',
                '60',
                '/usr/local/bin/bun',
                '--no-env-file',
                target,
            ],
            65_000,
        )
        context.passed('native app IPC, isolated database and generation revocation')
    } finally {
        await context.command([
            ...context.compose,
            'exec',
            '-T',
            'rentnerproxy',
            'rm',
            '-f',
            '--',
            target,
        ])
    }
}
