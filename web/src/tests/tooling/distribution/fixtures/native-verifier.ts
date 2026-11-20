import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export async function ensureNativeDistributionVerifier() {
    if (
        process.env.RENTNERPROXY_DISTRIBUTION_VERIFY ||
        Bun.which('rentnerproxy-distribution-verify')
    )
        return
    const crate = fileURLToPath(
        new URL('../../../../../../core/distribution-tooling/', import.meta.url),
    )
    const target = join(crate, 'target')
    const result = Bun.spawn(
        [
            'cargo',
            'build',
            '--locked',
            '--manifest-path',
            join(crate, 'Cargo.toml'),
            '--target-dir',
            target,
        ],
        { stdout: 'ignore', stderr: 'inherit' },
    )
    if ((await result.exited) !== 0) throw new Error('Failed to build native distribution verifier')
    process.env.RENTNERPROXY_DISTRIBUTION_VERIFY = join(
        target,
        'debug',
        process.platform === 'win32'
            ? 'rentnerproxy-distribution-verify.exe'
            : 'rentnerproxy-distribution-verify',
    )
}
