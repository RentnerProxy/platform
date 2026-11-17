const { port2 } = new MessageChannel()
window.parent.postMessage(
    { type: 'runtime:ready', nonce: location.hash.slice(1) },
    location.origin,
    [port2],
)
