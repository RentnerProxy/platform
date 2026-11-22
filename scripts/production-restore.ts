import { chmod, mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readDeploymentEnvironmentVariable } from '../web/src/lib/Environment/deployment-environment.ts'
import { BACKUP_RUNTIME_POLICY } from '../web/src/config/backup-runtime.config.ts'
import { PORTABLE_APP_BACKUP_VERSION } from '../web/src/config/compatibility.config.ts'

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url))
const defaultComposeFile = join(repositoryRoot, 'docker-compose.yml')
const applianceService = 'rentnerproxy'
const databaseHost = '127.0.0.1'
const bootstrapScript = '/opt/rentnerproxy/web/docker/web/bootstrap-secrets.ts'
const healthcheckScript = '/opt/rentnerproxy/web/docker/web/healthcheck.ts'
import {
    postgresCommand,
    controllerRestoreCommand,
    controllerMetadataValidationCommand,
    crowdSecRestoreCommand,
} from './backup/volume-commands.ts'
export { postgresCommand, postgresRestoreCommand } from './backup/volume-commands.ts'
import { waitForApplianceReadiness } from './backup/appliance-readiness.ts'
import { createMaintenanceCommands } from './backup/maintenance-commands.ts'
import { commandOption, composeArguments, readComposeProject } from './backup/compose.ts'
import { assertDeploymentCompatible } from './backup/format.ts'
import { snapshotProductionRestore } from './backup/restore-snapshot.ts'
import { appBackupCommand, appStateName } from './backup/app-state.ts'
import { deploymentSchema } from './backup/validation.ts'
import { smokeDockerArguments } from './smoke/resources.ts'

const commands = createMaintenanceCommands({
    cwd: repositoryRoot,
    operation: 'restore',
    transformArguments: smokeDockerArguments,
})

function optionValue(argumentsList: string[], name: string): string | undefined {
    return commandOption(argumentsList, name, 'restore')
}

function composeProject(argumentsList: string[]): string | undefined {
    return readComposeProject(argumentsList, process.env.COMPOSE_PROJECT_NAME, 'restore')
}

const composeCommand = composeArguments
const runCommand = commands.text

async function waitForAppliance(compose: string[]): Promise<void> {
    await waitForApplianceReadiness((timeoutMs) =>
        runCommand(
            [...compose, 'exec', '--no-TTY', applianceService, 'bun', healthcheckScript],
            'wait for appliance',
            timeoutMs,
        ),
    )
}

async function restore(): Promise<void> {
    const argumentsList = process.argv.slice(2)
    const inputOption = optionValue(argumentsList, '--input')
    if (!inputOption || !argumentsList.includes('--confirm-replace'))
        throw new Error('restore requires --input and --confirm-replace')
    const inputPath = resolve(inputOption)
    const snapshot = await mkdtemp(join(tmpdir(), 'rentnerproxy-restore-'))
    await chmod(snapshot, 0o700)
    try {
        // Only the bounded DNS registry and certificate index are retained for the pinned target image.
        const controllerDocuments: { kind: string; bytes: Uint8Array }[] = []
        const { metadata, backupId, stateCapacity } = await snapshotProductionRestore(
            inputPath,
            snapshot,
            undefined,
            (kind, bytes) => {
                controllerDocuments.push({ kind, bytes })
                return Promise.resolve()
            },
        )

        const portable = metadata.version === PORTABLE_APP_BACKUP_VERSION
        const appAware = portable ? PORTABLE_APP_BACKUP_VERSION : metadata.version === 5
        const resume = argumentsList.includes('--resume')
        const project = composeProject(argumentsList)
        const composeFile = resolve(process.env.RENTNERPROXY_COMPOSE_FILE ?? defaultComposeFile)
        await stat(composeFile)
        const compose = composeCommand(project, composeFile)
        const config = JSON.parse(
            await runCommand([...compose, 'config', '--format=json'], 'inspect deployment'),
        ) as {
            services: {
                rentnerproxy: { image: string; environment: Record<string, string | null> }
            }
        }
        const service = config.services.rentnerproxy
        const deployment = deploymentSchema.parse({
            publicOrigin: readDeploymentEnvironmentVariable('PUBLIC_ORIGIN', service.environment),
            trustedProxyCidrs:
                readDeploymentEnvironmentVariable(
                    'PROXY_TRUSTED_PROXY_CIDRS',
                    service.environment,
                ) ?? '',
        })
        assertDeploymentCompatible(
            metadata,
            deployment,
            argumentsList.includes('--allow-deployment-change'),
        )
        const imageId = await runCommand(
            ['docker', 'image', 'inspect', '--format={{.Id}}', service.image],
            'inspect restore image',
        )
        if (!/^sha256:[a-f0-9]{64}$/u.test(imageId)) throw new Error('invalid restore target image')
        for (const { kind, bytes } of controllerDocuments) {
            // oxlint-disable-next-line no-await-in-loop -- One owned validation container at a time.
            await commands.input(
                [
                    'docker',
                    'run',
                    '--rm',
                    '--network=none',
                    '--interactive',
                    '--entrypoint=bash',
                    imageId,
                    '-ceu',
                    controllerMetadataValidationCommand,
                    'metadata',
                    kind,
                    String(metadata.version),
                ],
                bytes,
                'validate controller backup metadata',
                30_000,
            )
        }
        const validation = await runCommand(
            [
                'docker',
                'run',
                '--rm',
                '--network=none',
                '--entrypoint=bash',
                '--volume',
                snapshot + ':/backup:ro',
                imageId,
                '-c',
                postgresCommand(true, '/backup', appAware),
            ],
            'restore PostgreSQL',
            BACKUP_RUNTIME_POLICY.databaseTimeoutMs,
        )
        let portableCapacity: string[] = []
        if (portable) {
            const size = /^PORTABLE_RESTORE_CAPACITY=([1-9][0-9]*),([1-9][0-9]*)$/u.exec(
                validation.split('\n').at(-1) ?? '',
            )
            if (!size || !size.slice(1).map(Number).every(Number.isSafeInteger))
                throw new Error('Isolated restore capacity evidence is unavailable')
            portableCapacity = [
                size[1]!,
                size[2]!,
                String(stateCapacity.controllerState.payloadBytes),
                String(stateCapacity.controllerState.nodes),
                String(stateCapacity.crowdSecState.payloadBytes),
                String(stateCapacity.crowdSecState.nodes),
            ]
        }

        const keyVolume = snapshot + ':/restore-key:ro'
        const archiveVolume = snapshot + ':/backup:ro'
        const bootstrap = (operation: string) => [
            ...compose,
            'run',
            '--no-TTY',
            '--rm',
            '--no-deps',
            '--entrypoint=bun',
            '--env',
            'RENTNERPROXY_DATABASE_HOST=' + databaseHost,
            '--env',
            'RENTNERPROXY_RESTORE_BACKUP_ID=' + backupId,
            '--env',
            'RENTNERPROXY_RESTORE_RESUME=' + resume,
            '--volume',
            keyVolume,
            applianceService,
            bootstrapScript,
            operation,
        ]
        const pending = await runCommand(
            bootstrap('inspect-production-restore'),
            'inspect pending restore',
        )
        if (pending && (!resume || pending !== backupId))
            throw new Error('interrupted restore requires --resume with the same backup')
        if (!pending && resume) throw new Error('no interrupted restore is pending')
        const previouslyRunning =
            !pending &&
            (await runCommand(
                [...compose, 'ps', '--status', 'running', '--quiet', applianceService],
                'inspect restore target',
            )) !== ''
        await runCommand(
            [
                ...compose,
                'stop',
                '--timeout',
                String(BACKUP_RUNTIME_POLICY.applianceStopGraceSeconds),
                applianceService,
            ],
            'quiesce restore target',
            180_000,
        )
        // A completed inventory rejection is a normal container exit. This lets the
        // maintenance runner verify --rm cleanup separately from the inventory verdict.
        try {
            const inventory = await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=bash',
                    '--volume',
                    archiveVolume,
                    applianceService,
                    '-c',
                    portable
                        ? 'if ! bun --no-env-file /opt/rentnerproxy/web/backup-export.js --check-portable-restore-capacity "${@:2}" >&2; then echo insufficient-capacity; elif bash -c "$1" >&2; then echo accepted; else echo rejected; fi'
                        : 'if bash -c "$1" >&2; then echo accepted; else echo rejected; fi',
                    'inventory',
                    postgresCommand('inventory', '/backup', appAware, backupId, resume),
                    ...portableCapacity,
                ],
                'check target application inventory',
                appAware ? BACKUP_RUNTIME_POLICY.databaseTimeoutMs : 180_000,
            )
            if (inventory === 'insufficient-capacity')
                throw new Error(
                    'Portable application restore target lacks verified storage capacity',
                )
            if (inventory !== 'accepted')
                throw new Error(
                    portable
                        ? 'Portable application restore requires verified releases and a fresh application target or the same interrupted restore'
                        : 'Could not check target application inventory',
                )
        } catch (error) {
            if (previouslyRunning) {
                commands.assertRestartSafe()
                try {
                    await runCommand(
                        [...compose, 'start', applianceService],
                        'restart restore target after preflight failure',
                        180_000,
                    )
                    await waitForAppliance(compose)
                } catch (cause) {
                    throw new Error(
                        'Preflight failed before the restore journal was created. Start the appliance with docker compose start rentnerproxy in the same Compose project and check readiness before retrying.',
                        { cause },
                    )
                }
            }
            throw error
        }
        // Preparing a fresh database must never boot the old controller/web workers.
        // A resumed restore already has its initialized cluster and must retain its journal/key state.
        if (!pending)
            await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=/usr/local/bin/rentnerproxy-production',
                    applianceService,
                    '--initialize-restore-target',
                ],
                'initialize restore target',
                180_000,
            )
        // The journal hook durably pauses root-owned off-host uploads and retention on
        // fresh and resumed restores before changing keys or restarting any writers.
        try {
            await runCommand(
                bootstrap('begin-production-restore'),
                'stage production restore and pause off-host backups',
            )
        } catch (error) {
            // runCommand exposes only its sanitized operation/cleanup message, never bootstrap stderr.
            const failure =
                error instanceof Error
                    ? error.message
                    : 'production restore operation failed: stage production restore and pause off-host backups'
            throw new Error(
                failure +
                    '. Restore staging interrupted; appliance remains stopped. If the restore journal was written, rerun the same backup with --resume --confirm-replace.',
                { cause: error },
            )
        }
        try {
            await runCommand(
                bootstrap('begin-app-key-restore'),
                'stage application encryption key restore',
            )
            await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=bash',
                    '--env',
                    'RENTNERPROXY_RESTORE_PHASE=database',
                    '--volume',
                    archiveVolume,
                    applianceService,
                    '-c',
                    postgresCommand(false),
                ],
                'restore PostgreSQL',
                BACKUP_RUNTIME_POLICY.databaseTimeoutMs,
            )

            await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=bash',
                    '--volume',
                    archiveVolume,
                    applianceService,
                    '-c',
                    controllerRestoreCommand(appAware),
                ],
                'restore controller state',
                BACKUP_RUNTIME_POLICY.captureTimeoutMs,
            )
            await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=bash',
                    '--volume',
                    archiveVolume,
                    applianceService,
                    '-c',
                    crowdSecRestoreCommand(),
                ],
                'restore managed CrowdSec state',
                BACKUP_RUNTIME_POLICY.captureTimeoutMs,
            )
            if (metadata.version === 5)
                await runCommand(
                    [
                        ...compose,
                        'run',
                        '--no-TTY',
                        '--rm',
                        '--no-deps',
                        '--entrypoint=' + appBackupCommand,
                        '--volume',
                        archiveVolume,
                        applianceService,
                        '--app-backup',
                        'restore',
                        '/backup/' + appStateName,
                    ],
                    'restore verified application files',
                    BACKUP_RUNTIME_POLICY.captureTimeoutMs,
                )
            if (portable)
                await runCommand(
                    [
                        ...compose,
                        'run',
                        '--no-TTY',
                        '--rm',
                        '--no-deps',
                        '--entrypoint=bash',
                        '--volume',
                        archiveVolume,
                        applianceService,
                        '-c',
                        postgresCommand('portable-apps', '/backup', PORTABLE_APP_BACKUP_VERSION),
                    ],
                    'restore portable application state and databases',
                    BACKUP_RUNTIME_POLICY.databaseTimeoutMs,
                )
            await runCommand(
                [
                    ...compose,
                    'run',
                    '--no-TTY',
                    '--rm',
                    '--no-deps',
                    '--entrypoint=sync',
                    applianceService,
                    '--file-system',
                    '/var/lib/rentnerproxy',
                ],
                'flush restored state',
            )
            await runCommand(
                bootstrap('complete-app-key-restore'),
                'complete application encryption key restore',
            )
            await runCommand(
                bootstrap('complete-production-restore'),
                'complete production restore',
            )
        } catch (error) {
            const failure =
                error instanceof Error ? error.message : 'production restore operation failed'
            throw new Error(
                failure +
                    '. Restore interrupted; appliance remains stopped; rerun the same backup with --resume --confirm-replace',
                { cause: error },
            )
        }
        await runCommand(
            [...compose, 'up', '--detach', '--force-recreate', applianceService],
            'start restored appliance',
            600_000,
        )
        await waitForAppliance(compose)
        console.log('Production restore completed from: ' + inputPath)
    } finally {
        await rm(snapshot, { force: true, recursive: true })
    }
}

if (import.meta.main) {
    try {
        await restore()
    } catch (error) {
        const message = error instanceof Error ? error.message : 'unknown restore error'
        console.error(
            'Production restore failed: ' +
                message +
                '. No automatic destructive retry was attempted.',
        )
        process.exitCode = 1
    }
}
