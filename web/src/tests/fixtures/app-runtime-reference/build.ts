import { copyFile, mkdir } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'
import { uiAssets } from './ui-assets.ts'

const [outputDirectory] = Bun.argv.slice(2)
if (!outputDirectory || !isAbsolute(outputDirectory)) {
    throw new Error('Usage: build.ts <absolute-ui-output-directory>')
}

await mkdir(outputDirectory, { recursive: true })
const source = join(import.meta.dir, 'ui')
const bundle = await Bun.build({
    entrypoints: [join(source, 'app.ts')],
    outdir: outputDirectory,
    target: 'browser',
    format: 'iife',
})
if (!bundle.success) {
    throw new AggregateError(bundle.logs, 'The reference UI build failed')
}
await Promise.all(
    Object.keys(uiAssets)
        .filter((filename) => filename !== 'app.js')
        .map((filename) => copyFile(join(source, filename), join(outputDirectory, filename))),
)
