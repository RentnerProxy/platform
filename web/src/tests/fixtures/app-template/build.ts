import { copyFile, mkdir } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'

const source = import.meta.dir

async function buildUi(directory: string) {
    const ui = join(source, 'ui')
    await mkdir(directory, { recursive: true })
    const result = await Bun.build({
        entrypoints: [join(ui, 'app.tsx')],
        outdir: directory,
        format: 'iife',
        target: 'browser',
        define: { 'process.env.NODE_ENV': JSON.stringify('production') },
        minify: true,
    })
    if (!result.success) throw new AggregateError(result.logs, 'Greeting UI build failed')
    await Promise.all(
        ['index.html', 'app.css'].map((name) => copyFile(join(ui, name), join(directory, name))),
    )
}

async function buildPackage(
    directory: string,
    repositoryId: string,
    commit: string,
    requestedTarget?: string,
) {
    if (process.platform !== 'linux' || (process.arch !== 'x64' && process.arch !== 'arm64')) {
        throw new Error('Package compilation requires native AMD64 or ARM64 Linux')
    }
    if (!/^[1-9][0-9]{0,19}$/u.test(repositoryId) || !/^[a-f0-9]{40}$/u.test(commit)) {
        throw new Error('A numeric repository ID and exact source commit are required')
    }
    const target = requestedTarget ?? (process.arch === 'x64' ? 'linux-amd64' : 'linux-arm64')
    if (target !== 'linux-amd64' && target !== 'linux-arm64')
        throw new Error('Unsupported package target')
    await mkdir(directory)
    const bin = join(directory, 'bin')
    const api = join(directory, 'api')
    await Promise.all([mkdir(bin), mkdir(api), buildUi(join(directory, 'ui'))])
    const backend = Bun.spawn(
        [
            process.execPath,
            '--no-env-file',
            'build',
            '--compile',
            '--no-compile-autoload-dotenv',
            '--no-compile-autoload-bunfig',
            '--target=' + (target === 'linux-amd64' ? 'bun-linux-x64-baseline' : 'bun-linux-arm64'),
            join(source, 'backend.ts'),
            '--outfile',
            join(bin, 'app'),
        ],
        { stdout: 'inherit', stderr: 'inherit' },
    )
    if ((await backend.exited) !== 0) throw new Error('Greeting backend compilation failed')
    const declaration: object = await Bun.file(join(source, 'manifest.json')).json()
    const manifest = {
        ...declaration,
        source: { repositoryId, commit },
        target,
    }
    await Promise.all([
        Bun.write(join(directory, 'app.json'), JSON.stringify(manifest) + '\n'),
        copyFile(join(source, 'openapi.json'), join(api, 'openapi.json')),
        copyFile(join(source, 'LICENSE'), join(directory, 'LICENSE')),
    ])
}

const [mode, directory, repositoryId, commit, target] = Bun.argv.slice(2)
if (!directory || !isAbsolute(directory))
    throw new Error('An absolute output directory is required')
if (mode === 'ui' && !repositoryId && !commit) {
    await buildUi(directory)
} else if (mode === 'package' && repositoryId && commit) {
    await buildPackage(directory, repositoryId, commit, target)
} else {
    throw new Error(
        'Usage: build.ts ui <directory> | package <directory> <repository-id> <commit> [linux-amd64|linux-arm64]',
    )
}
