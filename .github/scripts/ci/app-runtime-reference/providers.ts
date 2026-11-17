import assert from 'node:assert/strict'

export async function exerciseProviders(
    call: (request: Record<string, unknown>) => Promise<{ status: number; body: unknown }>,
): Promise<string[]> {
    async function expectReply(
        request: { operation: string } & Record<string, unknown>,
        status: number,
        body: unknown,
    ) {
        const response = await call(request)
        assert.equal(response.status, status, `${request.operation} status`)
        assert.deepEqual(response.body, body, `${request.operation} body`)
    }

    const monitor = { operation: 'monitor', limit: 1 }
    const samples = { samples: [{ service: 'proxy', healthy: true }] }
    await expectReply(monitor, 200, samples)
    await expectReply({ ...monitor, limit: 3 }, 400, { error: 'invalidLimit' })
    assert.equal((await call({ ...monitor, write: true })).status, 422, 'monitoring is read-only')
    await expectReply(monitor, 200, samples)

    const ownedRecord = { host: 'discovered.test', owner: 'docker-discovery', port: 8080 }
    const manualRecord = { host: 'manual.test', owner: 'operator', port: 9000 }
    const upsert = { operation: 'discoveryUpsert', host: 'discovered', port: 8080 }
    const readDiscovery = { operation: 'discoveryRead' }
    await expectReply(upsert, 200, ownedRecord)
    await expectReply({ ...upsert, port: 8081 }, 200, { ...ownedRecord, port: 8081 })
    await expectReply({ ...readDiscovery, host: 'manual' }, 200, manualRecord)
    await expectReply({ ...upsert, host: 'manual' }, 403, { error: 'foreignOwner' })
    await expectReply({ ...readDiscovery, host: 'manual' }, 200, manualRecord)
    await expectReply({ ...readDiscovery, host: 'discovered' }, 200, {
        ...ownedRecord,
        port: 8081,
    })

    const contribution = { revision: 1, policy: 'roundRobin', upstreams: ['127.0.0.1:8080'] }
    const applyEngine = { operation: 'engineApply', availability: 'available', contribution }
    const readEngine = { operation: 'engineRead' }
    const appliedEngine = { appliedContribution: contribution }
    await expectReply(applyEngine, 200, appliedEngine)
    assert.equal(
        (
            await call({
                ...applyEngine,
                contribution: { ...contribution, revision: 2, policy: 'rawConfig' },
            })
        ).status,
        422,
        'engine requires a typed balancing policy',
    )
    await expectReply(
        { ...applyEngine, contribution: { ...contribution, revision: 2, upstreams: [] } },
        400,
        { error: 'invalidContribution' },
    )
    await expectReply(readEngine, 200, appliedEngine)
    await expectReply(
        {
            ...applyEngine,
            availability: 'unavailable',
            contribution: {
                revision: 2,
                policy: 'leastConnections',
                upstreams: ['127.0.0.1:8082'],
            },
        },
        503,
        { error: 'engineUnavailable' },
    )
    await expectReply(readEngine, 200, appliedEngine)

    const checkDns = { operation: 'dnsCheck' }
    const cleanupDns = { operation: 'dnsCleanup' }
    const challenge = { challengePresent: true, servingCertificate: 'fixture-cert-1' }
    await expectReply({ operation: 'dnsPresent' }, 200, { ...challenge, outcome: 'presented' })
    await expectReply({ ...checkDns, observation: 'resolved' }, 200, {
        ...challenge,
        outcome: 'verified',
    })
    await expectReply({ ...checkDns, observation: 'missing' }, 409, {
        ...challenge,
        outcome: 'challengeMissing',
    })
    await expectReply({ ...checkDns, observation: 'unavailable' }, 503, {
        ...challenge,
        outcome: 'providerUnavailable',
    })
    await expectReply({ ...cleanupDns, availability: 'unavailable' }, 503, {
        ...challenge,
        outcome: 'providerUnavailable',
    })
    await expectReply({ ...checkDns, observation: 'resolved' }, 200, {
        ...challenge,
        outcome: 'verified',
    })
    await expectReply({ ...cleanupDns, availability: 'available' }, 200, {
        ...challenge,
        challengePresent: false,
        outcome: 'cleanedUp',
    })
    await expectReply({ ...checkDns, observation: 'resolved' }, 409, {
        ...challenge,
        challengePresent: false,
        outcome: 'challengeMissing',
    })

    const projectIdentity = { operation: 'oidcProject' }
    await expectReply({ ...projectIdentity, proof: 'verified' }, 200, {
        identity: { subject: 'fixture-user', groups: ['fixture-users'] },
    })
    assert.equal(
        (await call({ ...projectIdentity, proof: 'verified', subject: 'injected' })).status,
        422,
        'identity projection rejects caller-supplied claims',
    )
    await expectReply({ ...projectIdentity, proof: 'invalid' }, 401, { error: 'invalidProof' })
    await expectReply({ ...projectIdentity, proof: 'unavailable' }, 503, {
        error: 'identityUnavailable',
    })

    const enforce = { operation: 'crowdSecEnforce' }
    await expectReply({ ...enforce, signal: 'allow' }, 200, {
        outcome: 'allow',
        allowed: true,
        cachedBlock: false,
    })
    await expectReply({ ...enforce, signal: 'unavailable' }, 503, {
        outcome: 'unavailable',
        allowed: false,
        cachedBlock: false,
    })
    await expectReply({ ...enforce, signal: 'deny' }, 403, {
        outcome: 'deny',
        allowed: false,
        cachedBlock: true,
    })
    await expectReply({ ...enforce, signal: 'unavailable' }, 503, {
        outcome: 'unavailable',
        allowed: false,
        cachedBlock: true,
    })

    return ['monitoring', 'docker-discovery', 'load-balancer', 'dns', 'oidc', 'crowdsec']
}
