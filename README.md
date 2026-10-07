# aioayla-lan

Async local control of Ayla Networks IoT modules over **Ayla LAN mode**: no cloud after a one-time LAN key fetch.

The module is the HTTP client. You register with it, it dials back to your callback address, performs a key exchange, then fetches commands and pushes property values. This library handles the registration heartbeat, the session crypto, the command queue and the callback endpoints, as framework-agnostic handlers you mount on any HTTP server under `/local_lan/`.

Values are passed through uninterpreted. What a property means is up to the caller.

## Behaviour worth knowing

- **Return the status `AylaLanServer.handle` gives you.** It answers 206 Partial Content while commands are queued, which makes the module fetch the next one at once instead of waiting for another notify. A queue of 50 reads drains in about 2 s.
- **Writes are acknowledged, when the module acks.** `await device.async_set_property(name, value, base_type)` returns once the module acks, about a second after it collects the write. It raises `WriteExpiredError` when the module does not collect the write within 30 s, `WriteRejectedError` when the module refuses it, and `WriteUnacknowledgedError` (a `WriteRejectedError`) when no ack comes within 10 s. A missing ack does not mean the write failed: modules only ack properties the cloud marks ack-enabled, a busy module can ack late, and modules also drop unknown names and out-of-range values silently. Read the property back to learn the outcome. `set_property` queues without waiting.
- **Read back after a write.** Modules do not reliably echo what they were sent, nor what a write changed elsewhere.
- **One command per payload.** A module may ignore a batched `cmds` array and re-key.
- **Queue semantics.** Writes go before reads. A newer write to a queued name replaces it, and a repeated read is asked once.
- **Session.** Heartbeat every 10 s, a third of the module's `keep_alive`. One failed heartbeat does not drop the session; 30 s without contact does. A module that accepts notifies but stops dialling back for 30 s is registered afresh, which makes it key-exchange again.
- **One LAN client at a time, and no cloud client writing `refresh`.** A cloud-side `refresh` makes some modules push their whole catalogue for minutes, during which they collect no commands.
- **Expect malformed requests on the callback port.** Some firmware leaks its cloud echo onto the LAN socket; the server rejecting it loses the ack of the write before it, though the write was applied.

Status: pre-alpha, tested against Fujitsu General (FGLair) air conditioners only.
