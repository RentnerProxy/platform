import type { CatalogInstallation, CatalogLifecycleInput, CatalogRelease } from './contract.ts'

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
