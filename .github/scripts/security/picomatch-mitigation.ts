import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { join, resolve } from 'node:path'

const patchedPackage = 'picomatch@4.0.7'
const advisory = 'GHSA-fc5q-39xc-vjpf'
const patchPath = 'patches/picomatch@4.0.7.patch'
const npmIntegrity =
    'sha512-qcJu88Q2IWqJsDD529JKMdwGm/dvInW4HvQnRwiH9JtihJvzGOscDtHE3x1pBKeUOTysQ8kVmLnJ2kJu7yhcGA=='
const patchSha256 = '550d716012d83ec38cb7c7001e2421a7bcbd4b4a61c34f12a0e936945808d15d'
const parserSha256 = '46c326dda81c8afdb936e69773d03a5233534ddfec054d74ce5bdb68ab8cc337'
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export type PicomatchMitigationProof = {
    package: typeof patchedPackage
    advisory: typeof advisory
    patchSha256: string
    parserSha256?: string
}

async function readRegularFile(path: string, maximumSize: number): Promise<Buffer> {
    const entry = await lstat(path)
    if (!entry.isFile() || entry.size < 1 || entry.size > maximumSize)
        throw new Error('Invalid dependency proof input')

    const file = await open(
        path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    )
    try {
        const stat = await file.stat()
        if (
            !stat.isFile() ||
            stat.dev !== entry.dev ||
            stat.ino !== entry.ino ||
            stat.size !== entry.size
        )
            throw new Error('Dependency proof input changed during verification')

        const bytes = Buffer.alloc(stat.size + 1)
        const { bytesRead } = await file.read(bytes, 0, bytes.length, 0)
        if (bytesRead !== stat.size)
            throw new Error('Dependency proof input changed during verification')
        return bytes.subarray(0, bytesRead)
    } finally {
        await file.close()
    }
}

function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Expected a dependency proof object')
    return value as Record<string, unknown>
}

function assertUniqueObjectKeys(source: string): void {
    // The native parsers validate syntax but keep only the last duplicate key.
    // Inspect strings, comments, and object delimiters in the validated text.
    const objects: Set<string>[] = []
    let previous = ''
    for (const [token] of source.matchAll(
        /"(?:[^"\\]|\\[\s\S])*"|\/\/[^\r\n\u2028\u2029]*|\/\*[\s\S]*?\*\/|[{}:]/g,
    )) {
        if (token.startsWith('/')) continue
        if (token === '{') objects.push(new Set())
        if (token === '}') objects.pop()
        if (token === ':') {
            const key = JSON.parse(previous) as string
            const keys = objects.at(-1)!
            if (keys.has(key)) throw new Error('Duplicate dependency proof object key')
            keys.add(key)
        }
        previous = token
    }
}

function hasPatchDeclaration(file: Record<string, unknown>): boolean {
    return object(file.patchedDependencies)[patchedPackage] === patchPath
}

function hasTrustedResolution(lock: Record<string, unknown>): boolean {
    let trusted = false
    for (const [key, resolution] of Object.entries(object(lock.packages))) {
        if (!Array.isArray(resolution) || typeof resolution[0] !== 'string' || !resolution[0])
            throw new Error('Invalid dependency lock resolution')
        if (
            key !== 'picomatch' &&
            !key.endsWith('/picomatch') &&
            !resolution[0].startsWith('picomatch@')
        )
            continue
        if (
            trusted ||
            key !== 'picomatch' ||
            resolution.length !== 4 ||
            resolution[0] !== patchedPackage ||
            resolution[1] !== '' ||
            Object.keys(object(resolution[2])).length !== 0 ||
            resolution[3] !== npmIntegrity
        )
            return false
        trusted = true
    }
    return trusted
}

function sha256(bytes: Buffer): string {
    return createHash('sha256').update(bytes).digest('hex')
}

export async function verifyPicomatchMitigation(
    sourceDirectory: string,
    installedParser?: string,
): Promise<PicomatchMitigationProof | null> {
    try {
        const directory = resolve(sourceDirectory)
        if (!(await lstat(directory)).isDirectory()) return null
        const root = await realpath(directory)
        if (!(await lstat(join(root, 'patches'))).isDirectory()) return null

        const [manifestBytes, lockBytes, patchBytes] = await Promise.all([
            readRegularFile(join(root, 'package.json'), 1024 * 1024),
            readRegularFile(join(root, 'bun.lock'), 4 * 1024 * 1024),
            readRegularFile(join(root, patchPath), 64 * 1024),
        ])
        if (sha256(patchBytes) !== patchSha256) return null

        const manifestText = utf8.decode(manifestBytes)
        const lockText = utf8.decode(lockBytes)
        const manifest = object(JSON.parse(manifestText) as unknown)
        const lock = object(Bun.JSONC.parse(lockText))
        assertUniqueObjectKeys(manifestText)
        assertUniqueObjectKeys(lockText)
        if (
            !hasPatchDeclaration(manifest) ||
            !hasPatchDeclaration(lock) ||
            !hasTrustedResolution(lock)
        )
            return null

        const proof = { package: patchedPackage, advisory, patchSha256 } as const
        if (installedParser === undefined) return proof
        const parserBytes = await readRegularFile(installedParser, 256 * 1024)
        return sha256(parserBytes) === parserSha256 ? { ...proof, parserSha256 } : null
    } catch {
        return null
    }
}

export function isMitigatedPicomatchAdvisory(
    packageName: string,
    entry: Record<string, unknown>,
): boolean {
    return (
        packageName === 'picomatch' &&
        entry.id === 1247710 &&
        entry.url === `https://github.com/advisories/${advisory}` &&
        entry.severity === 'high' &&
        typeof entry.vulnerable_versions === 'string' &&
        entry.vulnerable_versions.replace(/^[ \t]*<=[ \t]*/, '<=') === '<=4.0.7'
    )
}
