import { expect, test } from 'bun:test'
import { existsSync } from 'node:fs'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const gitBash = 'C:/Program Files/Git/bin/bash.exe'
const shell = process.platform === 'win32' && existsSync(gitBash) ? gitBash : Bun.which('bash')
const script = resolve(import.meta.dir, '../../../../../../docker/production/verify-platform.sh')

function shellPath(path: string): string {
    const normalized = path.replaceAll('\\', '/')
    return process.platform === 'win32'
        ? normalized.replace(/^([a-z]):\//iu, (_match, drive: string) => `/${drive.toLowerCase()}/`)
        : normalized
}

for (const scenario of [
    { name: 'AMD64 dynamic executable', accepted: true },
    { name: 'ARM64 dynamic executable', architecture: 'arm64', machine: 183, accepted: true },
    {
        name: 'static executable',
        interpreter: false,
        lddStatus: 1,
        accepted: true,
    },
    { name: 'static PIE executable', interpreter: false, accepted: true },
    { name: 'wrong copied binary architecture', machine: 183 },
    { name: 'AMD64 binary in an ARM64 image', architecture: 'arm64' },
    { name: 'wrong base image architecture', kernelMachine: 'aarch64' },
    { name: 'missing runtime library', linkage: 'libfixture.so => not found' },
    { name: 'invalid linkage', linkage: 'invalid ELF', lddStatus: 1 },
    { name: 'needed library without an interpreter', interpreter: false, neededLibrary: true },
    { name: 'invalid program headers', readelfStatus: 1 },
    { name: '32-bit executable', elfClass: 1 },
    { name: 'big-endian executable', endianness: 2 },
    { name: 'non-ELF executable', magic: 'nope' },
    { name: 'unsupported architecture', architecture: 's390x' },
    { name: 'unsupported operating system', os: 'windows' },
]) {
    test.skipIf(!shell)(`appliance platform verification: ${scenario.name}`, async () => {
        if (!shell) throw new Error('Bash is required for appliance platform verification tests.')
        const options = {
            architecture: 'amd64',
            kernelMachine: undefined as string | undefined,
            os: 'linux',
            machine: 62,
            elfClass: 2,
            endianness: 1,
            magic: '\x7fELF',
            linkage: 'libc.so.6 => /lib/fixture/libc.so.6',
            lddStatus: 0,
            interpreter: true,
            neededLibrary: false,
            readelfStatus: 0,
            accepted: false,
            ...scenario,
        }
        const directory = await mkdtemp(join(tmpdir(), 'rentnerproxy-platform-'))
        try {
            const tools = join(directory, 'tools')
            await mkdir(tools)
            const binary = Buffer.alloc(64)
            binary.write(options.magic, 'ascii')
            binary[4] = options.elfClass
            binary[5] = options.endianness
            binary.writeUInt16LE(options.machine, 18)
            await Promise.all([
                writeFile(join(directory, 'binary'), binary),
                writeFile(
                    join(tools, 'uname'),
                    '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo "$KERNEL_MACHINE" ;; *) exit 2 ;; esac\n',
                    { mode: 0o755 },
                ),
                writeFile(
                    join(tools, 'readelf'),
                    '#!/bin/sh\nprintf "%s\\n" "$ELF_HEADERS"\nexit "$READELF_STATUS"\n',
                    { mode: 0o755 },
                ),
                writeFile(
                    join(tools, 'ldd'),
                    '#!/bin/sh\nprintf "%s\\n" "$LINKAGE"\nexit "$LDD_STATUS"\n',
                    { mode: 0o755 },
                ),
            ])
            const child = Bun.spawn(
                [
                    shell,
                    '--noprofile',
                    '--norc',
                    '-c',
                    'export PATH="$TOOL_DIRECTORY:/usr/bin:/bin"; chmod +x "$TOOL_DIRECTORY"/*; exec /bin/sh "$VERIFY_SCRIPT" "$TARGET_OS" "$TARGET_ARCH" "$TEST_BINARY"',
                ],
                {
                    env: {
                        PATH: '/usr/bin:/bin',
                        TOOL_DIRECTORY: shellPath(tools),
                        VERIFY_SCRIPT: shellPath(script),
                        TEST_BINARY: shellPath(join(directory, 'binary')),
                        TARGET_OS: options.os,
                        TARGET_ARCH: options.architecture,
                        KERNEL_MACHINE:
                            options.kernelMachine ??
                            (options.architecture === 'arm64' ? 'aarch64' : 'x86_64'),
                        ELF_HEADERS: [
                            options.interpreter ? '  INTERP  0x00000100' : '',
                            options.neededLibrary ? '  0x01 (NEEDED)   libfixture.so' : '',
                        ].join('\n'),
                        READELF_STATUS: String(options.readelfStatus),
                        LINKAGE: options.linkage,
                        LDD_STATUS: String(options.lddStatus),
                    },
                    stdout: 'pipe',
                    stderr: 'pipe',
                },
            )
            const [stdout, stderr, status] = await Promise.all([
                new Response(child.stdout).text(),
                new Response(child.stderr).text(),
                child.exited,
            ])
            expect(status, stdout + stderr).toBe(options.accepted ? 0 : 1)
        } finally {
            await rm(directory, { recursive: true, force: true })
        }
    })
}
