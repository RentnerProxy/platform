import { APP_UI_PREFIX } from './paths.ts'

const script = { type: 'text/javascript; charset=utf-8', destination: 'script' }
const mimeTypes = new Map([
    ['js', script],
    ['mjs', script],
    ['css', { type: 'text/css; charset=utf-8', destination: 'style' }],
    ['svg', { type: 'image/svg+xml', destination: 'image' }],
    ['png', { type: 'image/png', destination: 'image' }],
    ['jpg', { type: 'image/jpeg', destination: 'image' }],
    ['jpeg', { type: 'image/jpeg', destination: 'image' }],
    ['webp', { type: 'image/webp', destination: 'image' }],
    ['avif', { type: 'image/avif', destination: 'image' }],
    ['gif', { type: 'image/gif', destination: 'image' }],
    ['ico', { type: 'image/x-icon', destination: 'image' }],
    ['woff', { type: 'font/woff', destination: 'font' }],
    ['woff2', { type: 'font/woff2', destination: 'font' }],
    ['ttf', { type: 'font/ttf', destination: 'font' }],
    ['otf', { type: 'font/otf', destination: 'font' }],
])

export function appUiAssetPolicy(origin: string, token: string): string {
    const source = origin + APP_UI_PREFIX + token + '/'
    return [
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        'frame-ancestors ' + origin,
        'script-src ' + source,
        'style-src ' + source,
        'img-src ' + source,
        'font-src ' + source,
        'sandbox allow-scripts',
    ].join('; ')
}

export function appUiAssetType(request: Request, path: string, document: boolean): string | null {
    const dest = request.headers.get('sec-fetch-dest')
    const mode = request.headers.get('sec-fetch-mode')
    if (document)
        return dest === 'iframe' &&
            mode === 'navigate' &&
            request.headers.get('sec-fetch-site') === 'same-origin'
            ? 'text/html; charset=utf-8'
            : null
    const file = path.slice(path.lastIndexOf('/') + 1)
    const dot = file.lastIndexOf('.')
    const type = dot > 0 ? mimeTypes.get(file.slice(dot + 1)) : undefined
    const origin = request.headers.get('origin')
    return (origin === null || origin === 'null') &&
        (mode === 'no-cors' || mode === 'cors') &&
        type?.destination === dest
        ? type.type
        : null
}
