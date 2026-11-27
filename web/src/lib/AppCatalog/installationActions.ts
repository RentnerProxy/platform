import type {
    CatalogEntry,
    CatalogInstallation,
    CatalogLifecycleInput,
    CatalogRelease,
} from './contract.ts'

export type CatalogBlockedRelease = {
    version: string
    availability: Exclude<CatalogEntry['availability'], 'available'>
}

export function catalogInstallationActions(
    installation: CatalogInstallation,
    catalogReady: boolean,
    reinstall: CatalogRelease | undefined,
): CatalogLifecycleInput[] {
    const { installationId, generation, version, archiveSha256, state, update, previous } =
        installation
    const expected = { generation, version, archiveSha256 }
    const request = (
        action: CatalogLifecycleInput['action'],
        target?: CatalogLifecycleInput['target'],
    ): CatalogLifecycleInput => ({ action, installationId, expected, ...(target && { target }) })
    // An update that needs a new approval opens the approval dialog instead of starting.
    switch (state) {
        case 'running':
            return [
                ...(update && catalogReady ? [request('update', update)] : []),
                request('deactivate'),
                ...(previous ? [request('rollback', previous)] : []),
                request('uninstall'),
            ]
        case 'disabled':
            return [request('reactivate'), request('uninstall')]
        case 'recoveryRequired':
            return [
                request('recover'),
                ...(previous ? [request('rollback', previous)] : []),
                request('uninstall'),
            ]
        case 'removing':
            return [request('uninstall')]
        case 'removed':
            return [
                ...(reinstall && catalogReady ? [request('reinstall', reinstall)] : []),
                request('purge'),
            ]
        case 'purging':
            return [request('purge')]
    }
}

function compareIdentifiers(left: string, right: string): number {
    const leftNumeric = /^[0-9]+$/u.test(left)
    const rightNumeric = /^[0-9]+$/u.test(right)
    if (leftNumeric && rightNumeric) {
        // Numeric identifiers have no leading zeros, so length orders them before their digits.
        if (left.length !== right.length) return left.length - right.length
    } else if (leftNumeric || rightNumeric) {
        return leftNumeric ? -1 : 1
    }
    return left < right ? -1 : left > right ? 1 : 0
}

/** Order two catalog versions by semantic version precedence. */
export function compareCatalogVersions(left: string, right: string): number {
    const [leftCore, leftPrerelease] = splitVersion(left)
    const [rightCore, rightPrerelease] = splitVersion(right)
    for (const [index, component] of leftCore.entries()) {
        const difference = component - (rightCore[index] ?? 0)
        if (difference !== 0) return difference
    }
    if (leftPrerelease === undefined || rightPrerelease === undefined) {
        if (leftPrerelease === rightPrerelease) return 0
        return leftPrerelease === undefined ? 1 : -1
    }
    for (const [index, identifier] of leftPrerelease.entries()) {
        const other = rightPrerelease[index]
        if (other === undefined) return 1
        const difference = compareIdentifiers(identifier, other)
        if (difference !== 0) return difference
    }
    return leftPrerelease.length === rightPrerelease.length ? 0 : -1
}

function splitVersion(version: string): [number[], string[] | undefined] {
    const separator = version.indexOf('-')
    const core = separator === -1 ? version : version.slice(0, separator)
    return [
        core.split('.').map(Number),
        separator === -1 ? undefined : version.slice(separator + 1).split('.'),
    ]
}

/** The newest listed release of an installed app, when the appliance cannot offer it. */
export function catalogBlockedRelease(
    installation: CatalogInstallation,
    entries: readonly CatalogEntry[],
): CatalogBlockedRelease | undefined {
    let newest: CatalogEntry | undefined
    for (const entry of entries) {
        if (
            entry.appId === installation.appId &&
            compareCatalogVersions(entry.version, installation.version) > 0 &&
            (!newest || compareCatalogVersions(entry.version, newest.version) > 0)
        )
            newest = entry
    }
    if (!newest || newest.availability === 'available') return undefined
    return { version: newest.version, availability: newest.availability }
}
