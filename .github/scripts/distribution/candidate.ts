import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { ociRecord } from '../lib/oci-layout.ts'
import { bundleFiles, verifyDistributionBundle } from './bundle.ts'
import { verifyDistributionNative } from './native-verifier.ts'
import type { distributionWorkflowIdentity } from './prepare.ts'

type Identity = ReturnType<typeof distributionWorkflowIdentity>

export function validateDistributionCandidate(
    raw: unknown,
    identity: Identity,
    archiveSha256: string,
) {
    const candidate = ociRecord(raw)
    if (
        !/^[a-f0-9]{64}$/u.test(archiveSha256) ||
        candidate.schemaVersion !== 1 ||
        candidate.status !== 'unassessed' ||
        Object.entries(identity).some(
            ([key, value]) => key !== 'runAttempt' && candidate[key] !== value,
        ) ||
        typeof candidate.runAttempt !== 'number' ||
        !Number.isSafeInteger(candidate.runAttempt) ||
        candidate.runAttempt < 1 ||
        candidate.runAttempt > identity.runAttempt
    )
        throw new Error('Unassessed distribution candidate identity mismatch')
    return {
        schemaVersion: 1,
        ...identity,
        runAttempt: candidate.runAttempt,
        status: 'unassessed',
        archiveSha256,
    }
}

export async function verifyCandidateDistribution(root: string, hash: string, identity: Identity) {
    await verifyDistributionBundle(root, hash, identity)
    const files = await bundleFiles(root)
    if (
        files.some((file) =>
            ['image-evidence.json', 'binding.json', 'candidate-bundle.json'].includes(file),
        )
    )
        throw new Error('Candidate bundle must not claim image assessment')
    const raw = ociRecord(JSON.parse(await readFile(join(root, 'image-candidate.json'), 'utf8')))
    return validateDistributionCandidate(raw, identity, String(raw.archiveSha256))
}

export async function validateDistributionReports(
    reports: string,
    identity: Identity,
    candidateBundleSha256: string,
) {
    await verifyDistributionNative('reports', reports, { identity, candidateBundleSha256 })
}

export async function readBoundDistribution(root: string, identity: Identity) {
    const bound = ociRecord(JSON.parse(await verifyDistributionNative('bound', root, identity)))
    const candidateHash = bound.candidateBundleSha256
    if (typeof candidateHash !== 'string' || !/^[a-f0-9]{64}$/u.test(candidateHash))
        throw new Error('Invalid native distribution binding response')
    return { candidateHash, imageEvidence: ociRecord(bound.imageEvidence) }
}

export async function verifyBoundDistribution(root: string, identity: Identity) {
    return (await readBoundDistribution(root, identity)).candidateHash
}
