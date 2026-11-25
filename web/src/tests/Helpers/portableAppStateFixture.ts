import { createHash } from 'node:crypto'

export const portableInstallation = {
    id: 'kiri-1',
    appId: 'dev.example.kiri',
    uid: 20000,
    generation: 3,
    authorityRecorded: true,
}

function digest(data: Buffer) {
    return { bytes: data.length, sha256: createHash('sha256').update(data).digest('hex') }
}

/** A synthetic portable app state with one installation, its data and one database. */
export function portableAppState() {
    const data = Buffer.from('{}')
    const database = Buffer.from('PGDMP')
    const header = Buffer.from(
        JSON.stringify({
            formatVersion: 2,
            installations: {
                [portableInstallation.id]: {
                    appId: portableInstallation.appId,
                    uid: portableInstallation.uid,
                    generation: portableInstallation.generation,
                    authorityRecorded: portableInstallation.authorityRecorded,
                },
            },
            members: [
                { kind: 'data', key: 'files', ...digest(data) },
                {
                    kind: 'database',
                    key: String(portableInstallation.uid),
                    ...digest(database),
                    allocationBytes: 1024 ** 2,
                },
            ],
        }),
    )
    const prefix = Buffer.alloc(12)
    prefix.write('RPAPPB2\0')
    prefix.writeUInt32BE(header.length, 8)
    const snapshot = Buffer.concat([prefix, header, data, database])
    return { snapshot, applications: { ...digest(snapshot), installations: [portableInstallation] } }
}
