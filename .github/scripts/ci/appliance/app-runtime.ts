import { fileURLToPath } from 'node:url'
import type { ApplianceProxyTrafficContext } from './Types/scenarios.types.ts'

export async function verifyApplianceAppRuntime(context: ApplianceProxyTrafficContext) {
    const source = fileURLToPath(new URL('../fixtures/production-app-runtime.ts', import.meta.url))
    const target = '/usr/local/lib/rentnerproxy-app-runtime-fixture.ts'
    const exec = ['docker', 'exec', context.recreatedId]
    const managerProgress = '/run/rentnerproxy/app-api/fixture-progress'
    let phase = 'copy'
    try {
        await context.command(['docker', 'cp', source, context.recreatedId + ':' + target])
        phase = 'permissions'
        await context.command([...exec, 'chown', 'root:root', '--', target])
        await context.command([...exec, 'chmod', '0555', target])
        phase = 'execution'
        await context.command(
            [...exec, 'timeout', '60', '/usr/local/bin/bun', '--no-env-file', target],
            65_000,
        )
        context.passed('native app IPC, isolated database and generation revocation')
    } catch (error) {
        const [appStage, managerStage] = await Promise.all([
            context
                .command([...exec, 'cat', '/var/lib/rentnerproxy/apps/20991/data/fixture-progress'])
                .catch(() => ''),
            context.command([...exec, 'cat', managerProgress]).catch(() => ''),
        ])
        if (/^failed at (?:preparation|activation|database|notification)$/u.test(appStage))
            console.error('Native app fixture ' + appStage)
        else if (
            /^(?:bridge readiness|registration|provisioning|launch|activation|app checks|revocation)$/u.test(
                managerStage,
            )
        )
            console.error('Native app manager failed at ' + managerStage)
        else console.error('Native app smoke command failed at ' + phase)
        throw error
    } finally {
        await context.commandFails([...exec, 'rm', '-f', '--', target, managerProgress])
    }
}
