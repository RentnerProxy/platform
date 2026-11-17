import type { ReadyMessage } from './protocol.ts'

const { port2 } = new MessageChannel()
window.parent.postMessage(
    { type: 'runtime:ready', nonce: location.hash.slice(1) } satisfies ReadyMessage,
    location.origin,
    [port2],
)
