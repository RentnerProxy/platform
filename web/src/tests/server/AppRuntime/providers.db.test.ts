import { expect, test } from 'bun:test'
import { eq } from 'drizzle-orm'

import { appRuntimeGenerations, appRuntimeGrants, appRuntimeInstallations } from '@/db/schema.ts'
import { APP_RUNTIME_SUPPORT_CAPABILITIES } from '@/server/AppRuntime/authority-policy.server.ts'

const integrationEnabled =
    process.env.RENTNERPROXY_DATABASE_INTEGRATION === '1' && Boolean(process.env.DATABASE_URL)
const integrationTest = integrationEnabled ? test : test.skip

const grant = (profile: string, allowService = true) => ({
    capability: APP_RUNTIME_SUPPORT_CAPABILITIES.provider,
    resourceId: profile,
    allowService,
})

integrationTest(
    'provider registrations are recorded per generation and served only to the granted live generation',
    async () => {
        const { db } = await import('@/db/index.ts')
        const { createAppRuntimeGateway } = await import('@/server/AppRuntime/gateway.server.ts')
        const { manageAppRuntime } = await import('@/server/AppRuntime/management.server.ts')
        const { executeAppRuntimeCall } = await import('@/server/AppRuntime/services.server.ts')

        const identity = {
            appId: 'test.providers',
            installationId: crypto.randomUUID(),
            generation: 1,
            uid: 40_461,
        }
        const token = 'provider-test-bridge'
        const shutdown = new AbortController()
        const gateway = createAppRuntimeGateway(
            token,
            shutdown.signal,
            executeAppRuntimeCall,
            manageAppRuntime,
        )
        const send = (target: typeof identity, path: string, body?: unknown) =>
            gateway(
                new Request('http://app-api' + path, {
                    method: body === undefined ? 'GET' : 'POST',
                    headers: {
                        Authorization: 'Bearer ' + token,
                        'X-App-Installation': target.installationId,
                        'X-App-Generation': String(target.generation),
                        'X-RentnerProxy-App-Uid': String(target.uid),
                        'X-RentnerProxy-App-Id': target.appId,
                        ...(body !== undefined && { 'Content-Type': 'application/json' }),
                    },
                    ...(body !== undefined && { body: JSON.stringify(body) }),
                }),
            )
        const generation = (number: number) => ({ ...identity, generation: number })
        const control = async (
            action: string,
            target: typeof identity,
            fields: Record<string, unknown> = {},
        ) =>
            (
                await send(target, '/internal/v1/app-generations/' + action, {
                    identity: target,
                    ...fields,
                })
            ).status
        const fetchProvider = (target: typeof identity, id: string) =>
            send(target, '/platform/v1/providers/' + id)
        // The broker asks the authority on the bridge before each provider invocation.
        const authorizeInvocation = async (target: typeof identity, providerId: string) => {
            const response = await send(target, '/internal/v1/app-generations/provider', {
                identity: target,
                providerId,
            })
            return {
                status: response.status,
                body: response.status === 200 ? await response.json() : undefined,
            }
        }
        const leaseExpiresAt = new Date(Date.now() + 60_000).toISOString()
        const dns = { id: 'dns-main', profile: 'dns', version: '1.0.0' }
        const monitor = { id: 'monitor-main', profile: 'monitoring', version: '1.0.0' }
        const register = (target: typeof identity, providerProfiles?: string[]) =>
            control('register', target, {
                leaseExpiresAt,
                capabilities: [],
                ...(providerProfiles !== undefined && { providerProfiles }),
            })
        const expireLease = () =>
            db
                .update(appRuntimeGenerations)
                .set({ leaseExpiresAt: new Date(Date.now() - 1_000) })
                .where(eq(appRuntimeGenerations.installationId, identity.installationId))

        try {
            // Generation 1: declare dns + monitoring, record, prove a preparing record is unreadable.
            expect(await register(identity, ['dns', 'monitoring'])).toBe(204)
            expect(await register(identity, ['monitoring', 'dns'])).toBe(204)
            expect(await register(identity, ['dns'])).toBe(409)
            expect(await register(identity)).toBe(409)
            expect(await register(generation(2), ['dns', 'dns'])).toBe(400)
            expect(await register(generation(2), ['unknown'])).toBe(400)

            const invalidBodies = [
                { providers: [] },
                { providers: [dns, dns] },
                { providers: [{ ...dns, version: '2.0.0' }] },
                { providers: [{ ...dns, profile: 'unknown' }] },
                { providers: [{ ...dns, extra: true }] },
                {
                    providers: Array.from({ length: 33 }, (_, index) => ({
                        ...dns,
                        id: 'p' + index,
                    })),
                },
                {},
            ]
            expect(
                await Promise.all(
                    invalidBodies.map((fields) => control('providers', identity, fields)),
                ),
            ).toEqual(invalidBodies.map(() => 400))

            expect(
                await control('providers', { ...identity, uid: 40_462 }, { providers: [dns] }),
            ).toBe(401)
            expect(
                await control(
                    'providers',
                    { ...identity, appId: 'other.providers' },
                    { providers: [dns] },
                ),
            ).toBe(401)
            expect(await control('providers', generation(9), { providers: [dns] })).toBe(404)
            expect(
                await control('providers', identity, {
                    providers: [dns, { ...dns, id: 'oidc-main', profile: 'oidc' }],
                }),
            ).toBe(403)
            expect(await control('providers', identity, { providers: [dns, monitor] })).toBe(204)
            expect(await control('providers', identity, { providers: [dns, monitor] })).toBe(204)
            expect(await control('providers', identity, { providers: [monitor, dns] })).toBe(409)
            expect(await control('providers', identity, { providers: [dns] })).toBe(409)

            // A grant is only valid for a profile this generation declared.
            expect(await control('grants', identity, { grants: [grant('oidc')] })).toBe(400)
            expect(await control('grants', identity, { grants: [grant('not-a-profile')] })).toBe(
                400,
            )
            expect(
                await control('grants', identity, {
                    grants: [grant('dns'), grant('monitoring', false)],
                }),
            ).toBe(204)
            expect((await fetchProvider(identity, dns.id)).status).toBe(401)
            expect((await authorizeInvocation(identity, dns.id)).status).toBe(401)

            expect(await control('activate', identity, { leaseExpiresAt })).toBe(204)
            const served = await fetchProvider(identity, dns.id)
            expect(served.status).toBe(200)
            expect(await served.json()).toEqual(dns)
            expect((await fetchProvider(identity, monitor.id)).status).toBe(404)
            expect((await fetchProvider(identity, 'unknown')).status).toBe(404)
            expect(await control('providers', identity, { providers: [dns, monitor] })).toBe(409)
            // An invocation needs the same live registration and service grant as the read.
            expect(await authorizeInvocation(identity, dns.id)).toEqual({ status: 200, body: dns })
            expect((await authorizeInvocation(identity, monitor.id)).status).toBe(404)
            expect((await authorizeInvocation(identity, 'unknown')).status).toBe(404)
            expect((await authorizeInvocation(identity, 'Not A Record')).status).toBe(400)
            expect(
                await control('provider', identity, { providerId: dns.id, profile: 'dns' }),
            ).toBe(400)

            // Replacing the live grants takes effect immediately.
            expect(await control('grants', identity, { grants: [] })).toBe(204)
            expect((await fetchProvider(identity, dns.id)).status).toBe(404)
            expect((await authorizeInvocation(identity, dns.id)).status).toBe(404)
            expect(await control('grants', identity, { grants: [grant('dns')] })).toBe(204)
            expect((await fetchProvider(identity, dns.id)).status).toBe(200)
            expect((await authorizeInvocation(identity, dns.id)).status).toBe(200)

            // Update: generation 2 supersedes generation 1 and never serves its registrations.
            const second = generation(2)
            const secondDns = { ...dns, id: 'dns-two' }
            expect(await register(second, ['dns', 'monitoring'])).toBe(204)
            expect(await control('providers', second, { providers: [secondDns] })).toBe(204)
            expect(await control('grants', second, { grants: [] })).toBe(204)
            expect((await fetchProvider(second, secondDns.id)).status).toBe(401)
            expect(await control('activate', second, { leaseExpiresAt })).toBe(204)
            expect((await fetchProvider(identity, dns.id)).status).toBe(401)
            expect((await authorizeInvocation(identity, dns.id)).status).toBe(401)
            expect(await control('providers', identity, { providers: [dns] })).toBe(409)
            // Rollback-like generation: cleared grants stay unserved until granted again.
            expect((await fetchProvider(second, secondDns.id)).status).toBe(404)
            expect((await fetchProvider(second, dns.id)).status).toBe(404)
            expect(await control('grants', second, { grants: [grant('dns')] })).toBe(204)
            const secondServed = await fetchProvider(second, secondDns.id)
            expect(secondServed.status).toBe(200)
            expect(await secondServed.json()).toEqual(secondDns)
            expect((await fetchProvider(second, dns.id)).status).toBe(404)

            // A later manifest that drops the profile ignores the stale grant and refuses new ones.
            const third = generation(3)
            expect(await register(third, ['monitoring'])).toBe(204)
            expect(await control('providers', third, { providers: [monitor] })).toBe(204)
            expect(await control('providers', third, { providers: [dns] })).toBe(403)
            expect(await control('grants', third, { grants: [grant('dns')] })).toBe(400)
            expect(await control('activate', third, { leaseExpiresAt })).toBe(204)
            expect((await fetchProvider(third, monitor.id)).status).toBe(404)
            expect(await control('grants', third, { grants: [grant('monitoring')] })).toBe(204)
            expect((await fetchProvider(third, monitor.id)).status).toBe(200)

            // Revocation is immediate.
            expect((await authorizeInvocation(third, monitor.id)).status).toBe(200)
            expect(await control('revoke', third)).toBe(204)
            expect((await fetchProvider(third, monitor.id)).status).toBe(401)
            expect((await authorizeInvocation(third, monitor.id)).status).toBe(401)
            expect(await control('providers', third, { providers: [monitor] })).toBe(409)

            // A manifest without providers cannot register any; an expired lease cannot record.
            const fourth = generation(4)
            expect(await register(fourth)).toBe(204)
            expect(await control('providers', fourth, { providers: [dns] })).toBe(403)
            expect(await control('activate', fourth, { leaseExpiresAt })).toBe(204)
            expect((await fetchProvider(fourth, dns.id)).status).toBe(404)
            const fifth = generation(5)
            expect(await register(fifth, ['dns'])).toBe(204)
            expect(await control('providers', fifth, { providers: [dns] })).toBe(204)
            expect(await control('grants', fifth, { grants: [grant('dns')] })).toBe(204)
            expect(await control('activate', fifth, { leaseExpiresAt })).toBe(204)
            expect((await fetchProvider(fifth, dns.id)).status).toBe(200)
            // A lease that expires between principal resolution and the read is 401, not 404.
            const { readAppRuntimeProviderInTransaction, resolveAppRuntimePrincipalInTransaction } =
                await import('@/server/AppRuntime/authority.server.ts')
            await expect(
                db.transaction(async (transaction) => {
                    const principal = await resolveAppRuntimePrincipalInTransaction(transaction, {
                        identity: fifth,
                    })
                    return readAppRuntimeProviderInTransaction(
                        transaction,
                        { ...principal, expiresAt: new Date(Date.now() - 1) },
                        dns.id,
                    )
                }),
            ).rejects.toMatchObject({ code: 'unauthorized' })
            await expireLease()
            expect((await fetchProvider(fifth, dns.id)).status).toBe(401)
            const sixth = generation(6)
            expect(await register(sixth, ['dns'])).toBe(204)
            await expireLease()
            expect(await control('providers', sixth, { providers: [dns] })).toBe(409)
        } finally {
            shutdown.abort()
            await db.transaction(async (tx) => {
                const { installationId } = identity
                await tx
                    .delete(appRuntimeGrants)
                    .where(eq(appRuntimeGrants.installationId, installationId))
                await tx
                    .delete(appRuntimeGenerations)
                    .where(eq(appRuntimeGenerations.installationId, installationId))
                await tx
                    .delete(appRuntimeInstallations)
                    .where(eq(appRuntimeInstallations.id, installationId))
            })
        }
    },
)
