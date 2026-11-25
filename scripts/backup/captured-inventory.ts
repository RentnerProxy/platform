import { appBackupInstallations } from './validation.ts'
import type { CapturedInstallations } from './Types/captured-inventory.types.ts'

// The encoded inventory travels in one shell argument, which Linux limits to 128 KiB.
const maximumEncodedBytes = 96 * 1024

/** Encodes a captured portable inventory for the database check of an offline dump. */
export function encodeCapturedInstallations(installations: CapturedInstallations): string {
    const encoded = Buffer.from(
        JSON.stringify(appBackupInstallations.parse(installations)),
    ).toString('base64')
    if (encoded.length > maximumEncodedBytes)
        throw new Error('Captured application inventory is too large')
    return encoded
}

export function decodeCapturedInstallations(encoded: string): CapturedInstallations {
    if (
        encoded.length > maximumEncodedBytes ||
        !/^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)
    )
        throw new Error('Invalid captured application inventory')
    return appBackupInstallations.parse(
        JSON.parse(
            new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
                Buffer.from(encoded, 'base64'),
            ),
        ),
    )
}
