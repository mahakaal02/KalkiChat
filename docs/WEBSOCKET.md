# WebSocket Protocol

Endpoint: `wss://api.kalkichat.example/v1/ws`

## Handshake

```
GET /v1/ws HTTP/1.1
Host: api.kalkichat.example
Upgrade: websocket
Sec-WebSocket-Protocol: kalki.v1
Sec-WebSocket-Key: ...
Authorization: Bearer <access_jwt>
```

The server validates the JWT, looks up the device, and registers it in Redis
under `device:<id>`. Heartbeats are 30s ping / pong.

## Event envelope

All frames are text JSON:

```json
{
  "type": "<event-type>",
  "id":   "<client-supplied uuid for correlation>",
  "ts":   <unix-millis>,
  "data": { ... }
}
```

## Client → Server

| Type                    | data fields                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| `message.send`          | `client_id`, `recipient_device_ids[]`, `envelope` (b64), `signature` (b64), `media_id?`  |
| `message.ack`           | `server_id` — receiver acknowledges receipt                                              |
| `message.read`          | `server_id[]` — receiver marks as read                                                   |
| `typing`                | `is_typing: bool`                                                                        |
| `prekeys.upload`        | `signed_prekey`, `signed_prekey_sig`, `one_time_prekeys[]`                               |
| `presence.ping`         | (none) — heartbeat                                                                       |

## Server → Client

| Type                    | data fields                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `message.persisted`     | `client_id`, `server_id`, `ts`                                                       |
| `message.recv`          | `server_id`, `sender_device_id`, `envelope`, `signature`, `media_id?`                |
| `message.delivered`     | `server_id`, `delivered_to`                                                          |
| `message.read`          | `server_id`, `read_by`                                                                |
| `key.rotate`            | `epoch` — server requests a fresh signed prekey                                       |
| `session.revoked`       | `reason: "admin_action" \| "key_rotation" \| "tampered"`                              |
| `security.alert`        | `code`, `severity`, `human_message`                                                   |
| `server.shutdown`       | `retry_after_ms` — drain notice                                                        |

## Error handling

If the server rejects a message, it sends:

```json
{ "type": "message.error", "client_id": "...", "code": "INVALID_SIG" }
```

Codes: `INVALID_SIG`, `RECIPIENT_UNKNOWN`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`,
`ENVELOPE_MALFORMED`, `SESSION_REVOKED`.

## Reconnect & backfill

After a reconnect, the client sends `presence.online` with the highest
`server_id` it has. The server streams any missed `message.recv` events in
order before resuming live delivery.
