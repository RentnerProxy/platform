import { randomUUID } from 'node:crypto'

export class AppRuntimeProblem extends Error {
    readonly status: number
    readonly code: string
    readonly title: string

    constructor(status: number, code: string, title: string) {
        super(title)
        this.status = status
        this.code = code
        this.title = title
    }

    document(requestId: string = randomUUID()) {
        return {
            type: 'urn:rentnerproxy:problem:' + this.code,
            title: this.title,
            status: this.status,
            code: this.code,
            requestId,
        }
    }

    response(requestId?: string): Response {
        return Response.json(this.document(requestId), {
            status: this.status,
            headers: { 'Content-Type': 'application/problem+json', 'Cache-Control': 'no-store' },
        })
    }
}
