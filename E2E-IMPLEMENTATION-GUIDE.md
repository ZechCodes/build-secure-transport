# Build Secure Transport — E2E Encryption Implementation Guide

Reference implementation derived from the ai-chat project (device-side Python) and zech.sh server (aichat subdomain). This guide maps the proven patterns to Build's architecture.

---

## 1. Cryptographic Primitives

### Algorithms

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Symmetric encryption | XSalsa20-Poly1305 (NaCl secretbox) | 32 bytes | AEAD — provides confidentiality + integrity |
| Key exchange | X25519 ECDH | 32 bytes | Elliptic curve Diffie-Hellman |
| Key derivation | HKDF-SHA256 | 32 bytes output | Derives symmetric key from ECDH shared secret |
| Request signing | Ed25519 | 32 bytes | Device identity + API request authentication |
| Nonce | Random | 24 bytes | Generated fresh per encryption operation |

### Constants

```
HKDF_SALT  = b"build-device-key"   (was b"aichat-device-key")
HKDF_INFO  = b"v1"
SECRETBOX_KEY_LEN  = 32
SECRETBOX_NONCE_LEN = 24
```

### Dependencies

**Python (device/agent):**
- `cryptography` — X25519, HKDF, Ed25519
- `PyNaCl` — SecretBox (XSalsa20-Poly1305)

**JavaScript (browser):**
- `tweetnacl` / `tweetnacl-js` — secretbox, scalarMult
- Web Crypto API — HKDF derivation

---

## 2. Key Hierarchy

```
Device (canonical authority)
├── Ed25519 keypair ─────── identity + request signing
├── X25519 keypair ──────── ECDH for browser key exchange
└── Encryption key ──────── 32 random bytes, generated once
    ├── Encrypts ALL outbound message content
    ├── Decrypts ALL inbound message content
    ├── Persisted in device config (0o600 permissions)
    └── Never sent to server; only shared via ECDH wrap

Browser Session (ephemeral)
├── Ephemeral X25519 keypair ── generated per rekey
└── Transport key ───────────── derived via ECDH with device
    └── Used ONLY to unwrap the device's encryption key
```

### Design Decisions

- **Static canonical key** — one symmetric key per device, not rotated. Simpler than per-message ratcheting. Acceptable trade-off: no forward secrecy if device key is extracted, but the key never leaves the device except wrapped in an ephemeral ECDH transport.
- **No Signal Protocol / Double Ratchet** — unnecessary complexity for this use case (agent↔user, not user↔user).
- **No prekey bundles** — devices are always online when rekey happens; no need for async key exchange.

---

## 3. Device Registration & Identity

### Flow

```
Device                          Server                          Browser (User)
  │                               │                               │
  ├── Generate Ed25519 keypair    │                               │
  ├── Generate X25519 keypair     │                               │
  │                               │                               │
  ├── POST /api/devices/register ►│                               │
  │   {public_key, x25519_public, │                               │
  │    name}                      │                               │
  │◄── {device_code, auth_url} ───┤                               │
  │                               │                               │
  │   (display auth_url to user)  │                               │
  │                               │◄── User opens auth_url ──────┤
  │                               │    User clicks "Approve"      │
  │                               │◄── POST /devices/authorize ──┤
  │                               │    {code, action: "approve",  │
  │                               │     browser_x25519_public}    │
  │                               │                               │
  ├── GET /api/devices/status ───►│                               │
  │   ?code={device_code}         │                               │
  │◄── {status: "approved",      │                               │
  │     device_id, ...}           │                               │
  │                               │                               │
  └── Save config to disk (0o600) │                               │
```

### Server-Side Storage

```sql
CREATE TABLE device (
  id              UUID PRIMARY KEY,
  name            VARCHAR(100) NOT NULL,
  public_key      TEXT NOT NULL,          -- base64(Ed25519 public)
  x25519_public   TEXT,                   -- base64(X25519 public)
  owner_user_id   UUID NOT NULL REFERENCES "user"(id),
  status          VARCHAR(20) DEFAULT 'offline',
  last_seen_at    TIMESTAMP WITH TZ,
  created_at      TIMESTAMP WITH TZ NOT NULL,
  updated_at      TIMESTAMP WITH TZ NOT NULL
);
```

### Device Config (client-side, persisted)

```json
{
  "device_id": "uuid",
  "device_name": "hostname",
  "private_key_b64": "base64(Ed25519 private)",
  "public_key_b64": "base64(Ed25519 public)",
  "x25519_private_b64": "base64(X25519 private)",
  "x25519_public_b64": "base64(X25519 public)",
  "encryption_key_b64": "base64(32 random bytes)",
  "base_url": "https://app.getbuild.ing"
}
```

File permissions: `0o600` (owner read/write only). Write atomically via temp file + `os.replace()`.

---

## 4. Key Exchange (Rekey) Protocol

Rekey delivers the device's canonical encryption key to a new browser session.

### Flow

```
Browser                         Server                         Device
  │                               │                              │
  ├── Generate ephemeral X25519   │                              │
  │   keypair (browserPriv,       │                              │
  │   browserPub)                 │                              │
  │                               │                              │
  ├── POST /c/{ch}/rekey ────────►│                              │
  │   {browser_x25519_public,     ├── WebSocket push ──────────►│
  │    request_id}                │   {event: "rekey-request",   │
  │                               │    browser_x25519_public,    │
  │                               │    request_id}               │
  │                               │                              │
  │   Browser ECDH:               │        Device ECDH:          │
  │   shared = X25519(            │        shared = X25519(      │
  │     browserPriv,              │          devicePriv,         │
  │     deviceX25519Pub)          │          browserPub)         │
  │   transportKey = HKDF(shared) │        transportKey = HKDF(  │
  │                               │          shared)             │
  │                               │                              │
  │                               │        Wrap canonical key:   │
  │                               │        ct, nonce = SecretBox(│
  │                               │          transportKey,       │
  │                               │          encryption_key)     │
  │                               │                              │
  │                               │◄── WebSocket: rekey_response │
  │                               │    {encrypted_key, nonce,    │
  │◄── SSE relay ─────────────────┤     request_id}              │
  │                               │                              │
  │   Unwrap:                     │                              │
  │   encKey = SecretBox.open(    │                              │
  │     ct, nonce, transportKey)  │                              │
  │   localStorage.set(key)       │                              │
```

### Implementation Notes

- Both sides derive the **same** transport key from the ECDH shared secret via HKDF.
- The transport key is ephemeral — used once to wrap/unwrap the canonical key, then discarded.
- `request_id` correlates the async request/response through the server relay.

### Python (Device Side)

```python
def handle_rekey(device_x25519_private_b64, browser_x25519_public_b64, encryption_key_b64):
    # 1. ECDH
    shared = X25519PrivateKey.from_private_bytes(
        b64decode(device_x25519_private_b64)
    ).exchange(
        X25519PublicKey.from_public_bytes(b64decode(browser_x25519_public_b64))
    )

    # 2. Derive transport key
    transport_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"build-device-key", info=b"v1"
    ).derive(shared)

    # 3. Wrap canonical encryption key
    box = nacl.secret.SecretBox(transport_key)
    nonce = nacl.utils.random(24)
    ct = box.encrypt(encryption_key_b64.encode(), nonce)

    return b64encode(ct.ciphertext), b64encode(nonce)
```

### JavaScript (Browser Side)

```javascript
async function initiateRekey(deviceX25519PublicB64) {
    const ephemeral = nacl.box.keyPair();
    const devicePub = base64Decode(deviceX25519PublicB64);

    // ECDH
    const shared = nacl.scalarMult(ephemeral.secretKey, devicePub);

    // HKDF
    const keyMaterial = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const transportKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: encode("build-device-key"), info: encode("v1") },
        keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    // Note: export transportKey as raw bytes for NaCl secretbox usage

    return { ephemeral, transportKey, requestId: crypto.randomUUID() };
}

function completeRekey(transportKeyBytes, encryptedKeyB64, nonceB64) {
    const ct = base64Decode(encryptedKeyB64);
    const nonce = base64Decode(nonceB64);
    const encKeyB64 = nacl.secretbox.open(ct, nonce, transportKeyBytes);
    const encKey = base64Decode(new TextDecoder().decode(encKeyB64));
    localStorage.setItem("build:device_master_key", base64Encode(encKey));
    return encKey;
}
```

---

## 5. Message Encryption/Decryption

### Envelope Format

All encrypted messages use a versioned JSON envelope before encryption:

```json
{
  "schema": "build-e2e-v1",
  "meta": {
    "channel_id": "ch-abc123",
    "message_id": "msg-456"
  },
  "content": "Hello, world!",
  "attachments": []
}
```

- `schema` — version identifier for forward compatibility
- `meta.channel_id` — prevents cross-channel replay attacks
- `meta.message_id` — prevents cross-message replay attacks (may be null on first send, then re-encrypted with ID after server assigns one)

### Encrypt (Device → Browser)

```python
def encrypt_message(encryption_key_b64, content, channel_id, message_id=None, attachments=None):
    payload = json.dumps({
        "schema": "build-e2e-v1",
        "meta": {"channel_id": channel_id, "message_id": message_id},
        "content": content,
        "attachments": attachments or []
    })

    key = b64decode(encryption_key_b64)
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(24)
    encrypted = box.encrypt(payload.encode("utf-8"), nonce)

    return b64encode(encrypted.ciphertext).decode(), b64encode(nonce).decode()
```

### Decrypt (Device ← Browser)

```python
def decrypt_message(encryption_key_b64, ciphertext_b64, nonce_b64, expected_channel_id, expected_message_id=None):
    key = b64decode(encryption_key_b64)
    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(b64decode(ciphertext_b64), b64decode(nonce_b64))
    envelope = json.loads(plaintext.decode("utf-8"))

    # Validate metadata to prevent replay
    meta = envelope.get("meta", {})
    if meta.get("channel_id") != expected_channel_id:
        raise ValueError("channel_id mismatch — possible replay")
    if expected_message_id and meta.get("message_id") != expected_message_id:
        raise ValueError("message_id mismatch — possible replay")

    return envelope["content"], envelope.get("attachments", [])
```

### Wire Format (WebSocket / HTTP)

Encrypted messages carry two fields alongside the usual message metadata:

```json
{
  "type": "send_message",
  "channel_id": "ch-abc123",
  "content": "",
  "encrypted_payload": "base64(...)",
  "nonce": "base64(...)",
  "sender": "claude"
}
```

- `content` is empty string when encrypted (server stores `"[encrypted]"`)
- `encrypted_payload` + `nonce` are the ciphertext and nonce

---

## 6. Server Responsibilities (Zero-Knowledge)

The server **never** has access to encryption keys or plaintext. Its role:

### What the server stores

| Table | Encrypted Fields | Notes |
|-------|-----------------|-------|
| `message` | `content = "[encrypted]"` | Server never stores actual plaintext or ciphertext |
| `channel` | `encrypted_channel_key`, `key_nonce` | Device's key wrapped for browser — server can't unwrap |
| `device` | `public_key`, `x25519_public` | Public keys only — server never has private keys |

### What the server relays (ephemerally)

- `encrypted_payload` + `nonce` in notifications/WebSocket pushes
- Rekey requests and responses between browser ↔ device
- History requests (device re-encrypts local plaintext for browser)

### Server API Endpoints

#### Device Registration
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/devices/register` | None | Submit Ed25519 + X25519 public keys |
| GET | `/api/devices/status` | None | Poll for approval status |
| GET | `/devices/authorize` | Session | Browser approval page |
| POST | `/devices/authorize` | Session + CSRF | Approve/deny device |

#### Key Exchange
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/c/{channel_id}/rekey` | Session | Browser initiates ECDH rekey |

#### Messages
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/messages` | Ed25519 | Agent sends encrypted message |
| GET | `/api/messages` | Ed25519 | Agent fetches messages |
| POST | `/c/{channel_id}/send` | Session + CSRF | Browser sends encrypted message |

#### Device WebSocket
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/device/ws` | Ed25519 | Persistent bidirectional connection |

### Request Authentication (Ed25519)

Device/agent signs every API request:

```
Signed message: "{timestamp}.{METHOD}.{path}"
Headers:
  X-Device-Id: {device_id}
  X-Timestamp: {unix_timestamp}
  X-Signature: base64(Ed25519.sign(message))
```

Server verifies signature against stored public key. Timestamp must be within acceptable drift window.

---

## 7. Data Flow: Complete Message Lifecycle

### User → Agent (Browser sends message)

```
Browser
  ├── Build envelope: {schema, meta: {channel_id}, content, attachments}
  ├── Encrypt: SecretBox(encryption_key, envelope) → {ct, nonce}
  ├── POST /c/{ch}/send {encrypted_payload: ct, nonce}
  │
Server
  ├── Store message: content="[encrypted]" in DB
  ├── If device online: push {encrypted_payload, nonce} via WebSocket
  │
Device
  ├── Receive WebSocket event
  ├── Decrypt: SecretBox.open(ct, nonce, encryption_key) → envelope
  ├── Validate: channel_id in meta matches expected
  ├── Store plaintext in local SQLite
  └── Forward plaintext to agent worker via IPC
```

### Agent → User (Device sends response)

```
Agent Worker
  ├── Generate response (plaintext)
  ├── Send to device manager via IPC
  │
Device Manager
  ├── Build envelope: {schema, meta: {channel_id}, content, attachments}
  ├── Encrypt: SecretBox(encryption_key, envelope) → {ct, nonce}
  ├── WebSocket: send_message {encrypted_payload: ct, nonce, content: ""}
  │
Server
  ├── Store message: content="[encrypted]", assigns message_id
  ├── Return message_id to device
  ├── Push notification to browser via SSE
  │
Device Manager
  ├── Re-encrypt with message_id bound in envelope meta
  ├── WebSocket: relay_content {encrypted_payload: ct2, nonce2}
  │
Server
  ├── Relay to browser via SSE (ephemeral, not persisted)
  │
Browser
  ├── Decrypt: SecretBox.open(ct2, nonce2, encryption_key) → envelope
  ├── Validate: channel_id + message_id in meta
  └── Render decrypted message
```

### History Sync (Browser requests past messages)

```
Browser
  ├── POST /c/{ch}/request-history {request_id, before?, limit?}
  │
Server
  ├── Relay to device via WebSocket
  │
Device
  ├── Query local SQLite for plaintext messages
  ├── Encrypt each message with canonical key
  ├── WebSocket: history_response {messages: [{encrypted_payload, nonce}, ...]}
  │
Server
  ├── Relay to browser via SSE
  │
Browser
  ├── Decrypt each message
  └── Render in chat
```

---

## 8. Database Schema (Server)

```sql
-- Device identity and public keys
CREATE TABLE device (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  name            VARCHAR(100) NOT NULL,
  public_key      TEXT NOT NULL,       -- Ed25519 public (base64)
  x25519_public   TEXT,                -- X25519 public (base64)
  owner_user_id   UUID NOT NULL REFERENCES "user"(id),
  status          VARCHAR(20) DEFAULT 'offline',
  last_seen_at    TIMESTAMPTZ
);

-- Channel with encrypted key material
CREATE TABLE channel (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  name                  VARCHAR(100) NOT NULL,
  public_key            TEXT NOT NULL,       -- Ed25519 public (base64)
  device_id             UUID REFERENCES device(id),
  created_by_user_id    UUID,
  working_directory     VARCHAR(500),
  additional_directories TEXT,               -- JSON array
  archived              BOOLEAN DEFAULT false,
  encrypted_channel_key TEXT,                -- Wrapped symmetric key (base64)
  key_nonce             TEXT                 -- Nonce for unwrapping (base64)
);

-- Messages — server stores "[encrypted]" placeholder only
CREATE TABLE message (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender          VARCHAR(10) NOT NULL,  -- "user", "claude", "event", "tools"
  content         TEXT NOT NULL,          -- plaintext OR "[encrypted]"
  user_id         UUID,
  channel_id      UUID REFERENCES channel(id),
  read_by_agent_at  TIMESTAMPTZ,
  read_by_user_at   TIMESTAMPTZ,
  attachments     JSONB
);

CREATE INDEX idx_message_created ON message(created_at);
CREATE INDEX idx_message_channel_created ON message(channel_id, created_at);
```

---

## 9. Local Storage (Device-Side)

The device stores plaintext in a local SQLite database (WAL mode) for agent processing.

```sql
CREATE TABLE messages (
  id          TEXT PRIMARY KEY,
  channel_id  TEXT NOT NULL,
  sender      TEXT NOT NULL,
  content     TEXT NOT NULL,       -- actual plaintext
  created_at  TEXT NOT NULL,
  attachments TEXT                 -- JSON
);

CREATE TABLE channels (
  id    TEXT PRIMARY KEY,
  name  TEXT NOT NULL
);
```

This is acceptable because:
- The device already has the encryption key in memory
- Agents need plaintext to process messages
- Security relies on OS-level access controls (file permissions, disk encryption)

---

## 10. Security Properties

| Property | Status | Implementation |
|----------|--------|----------------|
| Confidentiality | Yes | XSalsa20-Poly1305 authenticated encryption |
| Integrity | Yes | Poly1305 MAC detects tampering |
| Server zero-knowledge | Yes | Server never holds encryption keys or plaintext |
| Channel binding | Yes | `channel_id` in encrypted envelope prevents cross-channel replay |
| Message binding | Yes | `message_id` in encrypted envelope prevents cross-message replay |
| Transport security | Yes | ECDH transport key is ephemeral per browser session |
| Device authentication | Yes | Ed25519 signatures on all API requests |
| Forward secrecy | Limited | Transport keys are ephemeral, but canonical key is static |
| Key rotation | Not yet | Static canonical key — acceptable for v1 |

### Threat Model

**Protected against:**
- Server compromise (server never has plaintext or keys)
- Network eavesdropping (TLS + E2E encryption)
- Cross-channel replay (channel_id binding)
- Message tampering (Poly1305 MAC)
- Device impersonation (Ed25519 signatures)

**Not protected against (acceptable for v1):**
- Device compromise (plaintext in local SQLite, key in config)
- Browser compromise (key in localStorage)
- Key compromise retroactive decryption (no forward secrecy on canonical key)

---

## 11. Implementation Checklist

### Phase 1: Core Crypto Module (`build-secure-transport`)
- [ ] `crypto.py` — encrypt/decrypt (NaCl secretbox), X25519 keygen, HKDF
- [ ] `key_exchange.py` — KeyExchange class with ECDH + wrap/unwrap
- [ ] `device_config.py` — atomic config persistence with 0o600 permissions
- [ ] `auth.py` — Ed25519 request signing
- [ ] Unit tests for all of the above (see ai-chat test patterns)

### Phase 2: Server Integration (`build-web`)
- [ ] Device table + migration
- [ ] Channel table with `encrypted_channel_key` + `key_nonce`
- [ ] Message table with `content="[encrypted]"` support
- [ ] Device registration endpoints (register, status, authorize)
- [ ] Rekey relay endpoint
- [ ] WebSocket handler with Ed25519 auth on upgrade
- [ ] Message endpoints with encrypted payload pass-through
- [ ] Redis-backed device code flow (TTL=600s)

### Phase 3: Client Integration (`build-client`)
- [ ] Device auth flow (generate keys, register, poll for approval)
- [ ] WebSocket connection with Ed25519-signed upgrade
- [ ] Message encryption on send, decryption on receive
- [ ] Rekey handler (ECDH + wrap canonical key)
- [ ] History handler (encrypt local plaintext for browser)
- [ ] Local SQLite for plaintext message storage

### Phase 4: Browser Crypto (`build-web` frontend)
- [ ] `build-crypto.js` — NaCl secretbox encrypt/decrypt
- [ ] Rekey initiation (ephemeral X25519, ECDH, HKDF)
- [ ] Rekey completion (unwrap canonical key)
- [ ] localStorage persistence of encryption key
- [ ] Decrypt incoming SSE/notification payloads
- [ ] Encrypt outgoing messages before POST

---

## 12. Migration Path from ai-chat

The ai-chat implementation is the reference. Key adaptations for Build:

| ai-chat | Build | Change |
|---------|-------|--------|
| `aichat_crypto.py` | `build-secure-transport/crypto.py` | Rename, update HKDF salt |
| `aichat_device_auth.py` | `build-secure-transport/device_config.py` | Same pattern |
| `aichat_auth.py` | `build-secure-transport/auth.py` | Same pattern |
| `aichat_manager.py` | `build-client/manager.py` | Refactor — extract encryption from monolith |
| `aichat-crypto.js` | `build-web/static/js/build-crypto.js` | Rename, update localStorage keys |
| `zech.sh/controllers/aichat.py` | `build-web/controllers/device.py` | Extract relevant endpoints |
| `zech.sh/models/ai_chat_*.py` | `build-web/models/` | Rename tables, same schema |
| HKDF salt `aichat-device-key` | `build-device-key` | Namespace change |
| Schema `aichat-e2e-v1` | `build-e2e-v1` | Namespace change |
| localStorage `aichat:device_*` | `build:device_*` | Namespace change |
