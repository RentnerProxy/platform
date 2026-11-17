import { isIP } from 'node:net'

type DiscoveryHost = 'discovered' | 'manual'

interface EngineContribution {
    revision: number
    policy: 'roundRobin' | 'leastConnections'
    upstreams: string[]
}

export function isJsonObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function hasFields(value: Record<string, unknown>, ...keys: string[]): boolean {
    return (
        Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
    )
}

function isUnsignedInteger(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max
}

function isDiscoveryHost(value: unknown): value is DiscoveryHost {
    return value === 'discovered' || value === 'manual'
}

function isAvailability(value: unknown): value is 'available' | 'unavailable' {
    return value === 'available' || value === 'unavailable'
}

function parseUpstream(value: unknown): string | undefined {
    if (typeof value !== 'string') return

    const match = /^(\[[^\]]+\]|[^:]+):([0-9]+)$/.exec(value)
    if (!match || match[0] !== value) return
    const [, address, portText] = match
    const port = Number(portText)
    if (!address || !isUnsignedInteger(port, 65_535)) return
    if (isIP(address) === 4) return `${address}:${port}`
    if (!address.startsWith('[') || !address.endsWith(']')) return

    const [ip, scopeText, extra] = address.slice(1, -1).split('%')
    if (!ip || isIP(ip) !== 6 || extra !== undefined) return
    const scope = scopeText === undefined ? 0 : Number(scopeText)
    if (scopeText !== undefined && /^[0-9]+$/.exec(scopeText)?.[0] !== scopeText) return
    if (!isUnsignedInteger(scope, 0xffff_ffff)) return

    const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1)
    // Rust's SocketAddr displays IPv4-mapped IPv6 addresses with a dotted suffix.
    const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(canonical)
    let host = canonical
    if (mapped) {
        const high = Number.parseInt(mapped[1] ?? '', 16)
        const low = Number.parseInt(mapped[2] ?? '', 16)
        host = `::ffff:${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
    }
    return `[${host}${scope === 0 ? '' : `%${scope}`}]:${port}`
}

function parseContribution(value: unknown): EngineContribution | undefined {
    if (!isJsonObject(value) || !hasFields(value, 'revision', 'policy', 'upstreams')) return
    const { revision, policy, upstreams } = value
    if (!isUnsignedInteger(revision, 0xffff_ffff) || !Array.isArray(upstreams)) return
    if (policy !== 'roundRobin' && policy !== 'leastConnections') return

    const addresses: string[] = []
    for (const upstream of upstreams) {
        const address = parseUpstream(upstream)
        if (address === undefined) return
        addresses.push(address)
    }
    return { revision, policy, upstreams: addresses }
}

function error(status: number, code: string): Response {
    return Response.json({ error: code }, { status })
}

export class Providers {
    private discoveredPort: number | null = null
    private appliedContribution: EngineContribution | null = null
    private challengePresent = false
    private crowdSecBlockCached = false

    call(request: unknown): Response {
        if (!isJsonObject(request)) return error(422, 'invalidProviderRequest')

        switch (request.operation) {
            case 'monitor': {
                const { limit } = request
                if (!hasFields(request, 'operation', 'limit') || !isUnsignedInteger(limit)) break
                if (limit < 1 || limit > 2) return error(400, 'invalidLimit')
                const samples = [
                    { service: 'proxy', healthy: true },
                    { service: 'controller', healthy: true },
                ]
                return Response.json({ samples: samples.slice(0, limit) })
            }
            case 'discoveryRead': {
                const { host } = request
                if (!hasFields(request, 'operation', 'host') || !isDiscoveryHost(host)) break
                return this.discoveryRecord(host)
            }
            case 'discoveryUpsert': {
                const { host, port } = request
                if (!hasFields(request, 'operation', 'host', 'port')) break
                if (!isDiscoveryHost(host) || !isUnsignedInteger(port, 65_535)) break
                if (host === 'manual') return error(403, 'foreignOwner')
                if (port === 0) return error(400, 'invalidPort')
                this.discoveredPort = port
                return this.discoveryRecord(host)
            }
            case 'engineRead':
                if (!hasFields(request, 'operation')) break
                return this.engineState()
            case 'engineApply': {
                if (!hasFields(request, 'operation', 'availability', 'contribution')) break
                const contribution = parseContribution(request.contribution)
                const { availability } = request
                if (!isAvailability(availability) || !contribution) break
                if (availability === 'unavailable') return error(503, 'engineUnavailable')
                const appliedRevision = this.appliedContribution?.revision ?? 0
                if (
                    contribution.revision <= appliedRevision ||
                    contribution.upstreams.length === 0
                ) {
                    return error(400, 'invalidContribution')
                }
                this.appliedContribution = contribution
                return this.engineState()
            }
            case 'dnsPresent':
                if (!hasFields(request, 'operation')) break
                this.challengePresent = true
                return this.dnsResult(200, 'presented')
            case 'dnsCheck': {
                if (!hasFields(request, 'operation', 'observation')) break
                const { observation } = request
                if (observation === 'unavailable') return this.dnsResult(503, 'providerUnavailable')
                if (observation !== 'resolved' && observation !== 'missing') break
                if (observation === 'resolved' && this.challengePresent) {
                    return this.dnsResult(200, 'verified')
                }
                return this.dnsResult(409, 'challengeMissing')
            }
            case 'dnsCleanup': {
                const { availability } = request
                if (
                    !hasFields(request, 'operation', 'availability') ||
                    !isAvailability(availability)
                )
                    break
                if (availability === 'unavailable')
                    return this.dnsResult(503, 'providerUnavailable')
                this.challengePresent = false
                return this.dnsResult(200, 'cleanedUp')
            }
            case 'oidcProject': {
                if (!hasFields(request, 'operation', 'proof')) break
                const { proof } = request
                if (proof === 'invalid') return error(401, 'invalidProof')
                if (proof === 'unavailable') return error(503, 'identityUnavailable')
                if (proof !== 'verified') break
                return Response.json({
                    identity: { subject: 'fixture-user', groups: ['fixture-users'] },
                })
            }
            case 'crowdSecEnforce': {
                if (!hasFields(request, 'operation', 'signal')) break
                const { signal } = request
                if (signal === 'allow') this.crowdSecBlockCached = false
                else if (signal === 'deny') this.crowdSecBlockCached = true
                else if (signal !== 'unavailable') break

                const status = signal === 'allow' ? 200 : signal === 'deny' ? 403 : 503
                return Response.json(
                    {
                        outcome: signal,
                        allowed: signal === 'allow',
                        cachedBlock: this.crowdSecBlockCached,
                    },
                    { status },
                )
            }
        }

        return error(422, 'invalidProviderRequest')
    }

    private discoveryRecord(host: DiscoveryHost): Response {
        if (host === 'discovered') {
            return Response.json({
                host: 'discovered.test',
                owner: 'docker-discovery',
                port: this.discoveredPort,
            })
        }
        return Response.json({ host: 'manual.test', owner: 'operator', port: 9000 })
    }

    private engineState(): Response {
        return Response.json({ appliedContribution: this.appliedContribution })
    }

    private dnsResult(status: number, outcome: string): Response {
        return Response.json(
            {
                outcome,
                challengePresent: this.challengePresent,
                servingCertificate: 'fixture-cert-1',
            },
            { status },
        )
    }
}
