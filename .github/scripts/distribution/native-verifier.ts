import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { runMaintenanceProcess } from '../../../scripts/backup/maintenance-process.ts'

const outputLimits = {
    package: 4096,
    reports: 4096,
    bound: 2 * 1024 * 1024,
    compact: 24 * 1024 * 1024,
    'oci-input': 1024 * 1024,
}

export async function verifyDistributionNative(
    action: keyof typeof outputLimits,
    path: string | null,
    request: object | Uint8Array,
): Promise<string> {
    const executable =
        process.env.RENTNERPROXY_DISTRIBUTION_VERIFY || 'rentnerproxy-distribution-verify'
    const scratch =
        action === 'package' ? await mkdtemp(join(tmpdir(), 'rp-package-verify-')) : null
    try {
        const result = await runMaintenanceProcess(
            path === null ? [executable, action] : [executable, action, resolve(path)],
            {
                cwd: process.cwd(),
                timeoutMs: action === 'oci-input' ? 360_000 : 120_000,
                maximumOutputBytes: outputLimits[action],
                input:
                    request instanceof Uint8Array ? request : Buffer.from(JSON.stringify(request)),
                ...(scratch && {
                    env: { ...process.env, TMPDIR: scratch, TMP: scratch, TEMP: scratch },
                }),
            },
        )
        if (result.failed || !result.stopped) {
            const diagnostic = result.stderr.trim()
            throw new Error(
                /^[A-Za-z0-9 .-]{1,100}$/u.test(diagnostic)
                    ? diagnostic
                    : 'Native distribution verification failed',
            )
        }
        return Buffer.from(result.stdout).toString('utf8').trim()
    } finally {
        if (scratch) await rm(scratch, { recursive: true, force: true })
    }
}
