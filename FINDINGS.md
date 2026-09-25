# Findings: what `X-Codex-Turn-State` is and why reuse works

This documents what the plugin is actually manipulating. No token values, keys,
account identifiers, or infrastructure details appear here — only the structure
and the observable behaviour.

## The reuse rules (the spec this plugin enforces)

1. A `state` value **cannot** be reused across accounts.
2. A `state` value **cannot** be reused across models, even within one account.
3. A `state` value for the **same account + same model can be reused across IPs**.
4. A `state` value is usable for **~240 seconds** in practice, not the hour its
   signature allows.
5. A `state` value only persists while a **live `__cflb`/`__oailb` cookie pair
   of the same account** rides on the same request.

The plugin keys every template on `(account, model)` and never crosses either
boundary, which is exactly rules 1–3. Rules 4 and 5 are measured behaviour, and
each gets a section below.

## `X-Codex-Turn-State` is a Fernet token

The value is a Fernet token, base64url-encoded:

```
0x80  (1 byte, version)
ts    (8 bytes, big-endian Unix seconds — issuance time)
IV    (16 bytes)
ciphertext (AES-CBC, multiple of 16 bytes)
HMAC  (32 bytes)
```

Every observed value begins with the `0x80` version byte (`gAAAAA…` once
base64url-encoded). The 8-byte timestamp is the token's **issuance time**, and
it can be read without any key:

```python
import base64, struct
from datetime import datetime, timezone

def issued_at(token: str):
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    version = raw[0]                          # 0x80
    ts = struct.unpack(">Q", raw[1:9])[0]     # issuance time, Unix seconds
    return version, datetime.fromtimestamp(ts, timezone.utc)
```

Observed: the embedded timestamp equals the moment the value first appears on a
response, to the second. Tokens are **issued fresh per turn**, not recycled — so
every captured value starts its clock the instant it is minted.

The clock inside the token signs for an hour, but that is no longer the usable
window — see the next two sections.

## The ticket needs its load-balancer cookies (measured 2026-09-22)

The response that mints a 292 also sets two cookies: `__cflb` and `__oailb`.
Replaying the ticket without them does not hold — the upstream treats the
combination, not the ticket alone.

The measured sequence: a 292 minted through one colo (`IST`), then replayed
through a different exit (`Oracle`) together with the pair it was minted
alongside — accepted at ages 3s, 27s, 50s, …, last accepted at **192s**, and
refused at **267s** (the upstream answered by minting a fresh 312). Earlier
observations of the same failure sit between 65s and 220s. So the usable window
is **roughly 240s**, and which half dies first — ticket or cookies — is not
established; likely the cookies.

Two deliberate cross-checks matter more than the window:

- **Ticket ↔ cookie is not a binding.** Ticket A with cookie set B, and ticket B
  with cookie set A, were both accepted. Same for swapping tickets inside one
  `session_id`.
- **`__cflb`/`__oailb` are account-level routing credentials, not per-ticket
  ones.** Any live pair of the account serves any of its tickets.

What the plugin does with that: the pair is pooled **globally** — the
credential is account-agnostic, so one set serves every account — refreshed
off every upstream response that sets it (including responses that mint no
state at all) and attached to any outgoing request that can be steered. A set
is trusted for `ttl_seconds` from observation, shortened by the credential's
own deadline — the `__oailb` JWT's `exp` (signs 3900s, measured across 7
consecutive mints 2026-09-22) when the value carries one, else the declared
`Max-Age`/`Expires` (3600).

Only `__cflb`/`__oailb` are ever replayed. A Codex response sets other cookies
too — device identity, session material — and forwarding those would pin one
session's identity onto another client's traffic, so they are filtered out at
capture.

## Two lengths, and what the difference is

| State | base64 chars | decoded bytes |
|---|---:|---:|
| normal | 292 | 217 |
| throttled | 312 | 233 |

The difference is **exactly 16 bytes — one AES-CBC block**. The longer value is
not a different kind of token; it is the same structure carrying one extra
encrypted block. In practice:

- **292 (217 bytes)** corresponds to the normal serving state.
- **312 (233 bytes)** corresponds to the throttled/degraded serving state.

Because the extra content is inside the ciphertext, the state is invisible from
outside except through this length tell — which is what makes the 16-byte
difference a reliable, byte-exact indicator rather than a guess.

**The lengths are plan-differentiated (measured 2026-09-22).** Two credentials
on the same Apple id, fired side by side: a `prolite` account signed **292** on
every normal response (gpt-5.5 and gpt-5.6-sol, two different edge colos),
while a `self_serve_business_prolite` account signed **332** (249 bytes,
twelve ciphertext blocks) on every normal response across three models and two
exits. So the table above is a per-plan reading, not a universal one — and
`self_serve_business_prolite`'s "normal" already sits one block past the old
`prolite` "degraded", so no single global threshold separates the two classes.
What this means operationally — `template_length`/`replace_length` must be set
to whatever the deployment's own credentials sign, and a streak of `other`
classifications on visibly healthy traffic means the configured lengths
describe the wrong plan, not that every request failed.

**The classes also move with the format, not just the plan (measured
2026-09-22).** The upstream unified `X-Codex-Turn-State` onto a larger
payload: the same prolite credential, fired through six different edge colos
across seven models (gpt-5.5, gpt-5.6-sol/luna/terra, gpt-6-astra/sol/luna),
signed **780** on all 21 responses — where hours earlier the same bucket had
signed 292. The token is still a Fernet (`0x80` version, embedded issuance
timestamp, 528-byte ciphertext = 33 blocks, 32-byte HMAC); what grew is the
encrypted payload, roughly +368 bytes of new fields that are invisible from
outside. Length is no longer content-sensitive either: a bare "ping", a 4 KB
input, and a three-message turn all signed exactly 780. The official client
semantics are unchanged — a new turn's first request carries no state, the
first response mints it, and continuations replay that first value — so only
the signature size moved.

- No fixed whitelist of lengths can describe "normal" across a format change.
  The observation tally therefore learns per bucket: an unrecognised signed
  length files as `other` on first sighting and promotes to that bucket's
  `normal` once it recurs. `template_length` remains an anchor, not a
  whitelist.
- `replace_length` is still the only *measured* degraded signature, and it was
  measured on the old format. The new format's degraded signal could not be
  elicited on a healthy account (measured 2026-09-22): a 10-request serial
  burst and a 15-request parallel burst through one exit IP all returned
  200+780, and — more telling — replaying a stale 292, a truncated token, and
  outright garbage each minted a normal 780. The old "refusal mints a 312"
  path is gone: under the unified format every refusal/healing path signs the
  same length.

**Where the degraded signal moved (measured 2026-09-22).** Under the unified
format degradation is not a size — it is a **served-model switch**. Responses
carry two declarative headers whenever the requested model has a
safety-buffering fallback: `x-codex-safety-buffering-enabled: true` and
`x-codex-safety-buffering-faster-model: <model>`. The fallback map measured
across all seven models:

| requested | buffering headers | fallback |
|---|---|---|
| gpt-5.5 | absent | — |
| gpt-5.6-luna | absent | — |
| gpt-6-luna | absent | — |
| gpt-5.6-sol | present | gpt-5.6-luna |
| gpt-5.6-terra | present | gpt-5.6-luna |
| gpt-6-astra | present | gpt-5.6-luna |
| gpt-6-sol | present | gpt-6-luna |

The headers announce the chain on every healthy response — they mark
eligibility, not the event. The event itself is the SSE payload's
`response.model` declaring the fallback instead of the requested model (the
luna family is the sink: every chain ends at a luna variant). The plugin
therefore reads the first `"model"` field of the stream and files a mismatch
as `limited` — the same kind a 312 used to mean — and deprioritises the
steered pair the same way. If a degraded length signature still exists it is
inside the ciphertext (+368 B of new fields); until a throttled response is
captured, a NEW degraded length class would be learned as normal, which is
the standing trade-off of not hard-coding payload sizes.

**The fallback cannot be negotiated away (measured 2026-09-22).** Everything
request-side was tried on a healthy account: sending
`x-codex-safety-buffering-enabled: false` as a request header changes nothing
(the response still declares the chain); `service_tier:"default"` and
`"priority"` are accepted but the headers persist; `service_tier:"auto"` and
`"flex"` are rejected outright (`Unsupported service_tier`), and
`store:true` is rejected (`Store must be set to false`). Roughly fifty probe
requests across seven models, six gateway nodes (unified-125/95/88/157/97/
179 steered by replayed pairs), tool-carrying requests, high/xhigh effort,
serial and parallel bursts, and security-review prompts all returned
served==requested with a normal 780. There is no client knob that guarantees
served==requested — the buffering decision is the upstream's alone. What a
client-side stack can do is exactly what this plugin now does: detect the
switch on the stream and score the exit that produced it.

**Continuation mechanics (measured 2026-09-22).** `previous_response_id` is
rejected (`Unsupported parameter`): a turn continues by replaying the
`X-Codex-Turn-State` header alone. A replayed current state is accepted
silently — 200, correct model, and **no new state minted** — which is the
same "steered and accepted" reading the cookie path already produces.

**Hard request constraints on this endpoint (measured 2026-09-22).**
`store` must be `false`, `stream` must be `true`, `service_tier` accepts
only omission/`default`/`priority` (`auto`, `flex` rejected), and the
responses-lite header requires `reasoning.context:"all_turns"`. The official
client's extra headers (`x-codex-beta-features`, `x-openai-subagent`,
window id) change nothing observable.

**Direct gateway access is not a usable shortcut (measured 2026-09-23).**
The `chat.gateway.unified-N.api.openai.com` names in the `__oailb` JWT
resolve to ordinary Cloudflare edge IPs, not to dedicated node listeners.
Addressed with their own SNI they present a `*.gateway.unified-N` Let's
Encrypt cert and an HTTP service that answers 404s — but only sporadically:
TLS is fingerprint/rate gated and refuses nearly every handshake.
Addressing the same IP as `chatgpt.com` serves the normal backend-api
(200, chatgpt.com cert) — yet the pair it mints is for a DIFFERENT node
(unified-26's IP minted unified-95): the edge assigns the gateway node, the
IP does not choose it. So there is no path to a chosen node except the
`__cflb`/`__oailb` pair replay this plugin already does.

**`turn/steer` interaction (codex app-server, PR openai/codex#10690).** The
stable Steer surface (`turn/start` on an active turn, or `turn/steer` params
in the protocol) appends user input to an in-flight turn; it carries
`thread_id`, `input`, `expected_turn_id`, `responsesapi_client_metadata`
(flattened into the `x-codex-turn-metadata` request header) and
`additional_context` — and **no model field**: a steered turn inherits
whatever model the original request negotiated, fallback included. A mid-turn
model change needs `turn/settings/update`, which returns `Applied` or
`TargetUnavailable`. So a turn that opened on a buffered (luna) node keeps
steering input into that same degraded service — detection stays the lever,
there is no mid-turn escape either.

## Behaviour notes

- A request that lands in the degraded path commonly surfaces as
  `server_is_overloaded`. Treat that error together with a degraded reading —
  a 312-length state on the old format, a served-model switch on the unified
  one — as one signal, not two independent ones.
- `Encrypted content could not be decrypted` appears when a token is replayed
  after its window, or mid-rotation. This is the failure mode a naïve
  "inject any captured value" approach hits — and the reason expiry must be
  keyed on the token's own timestamp, not on when the proxy happened to see it.

## Transport surface changes (measured 2026-09-24)

Two upstream protocol surface changes were observed on this date, both breaking
cloud minting until the relay adapted:

- **SSE responses now arrive as `application/octet-stream`** with
  `Content-Disposition: attachment` instead of `text/event-stream`. The body is
  unchanged — the same `event:`/`data:` stream, `response.created` still carries
  `response.model`. The ticket header `x-codex-turn-state` and the
  `__cflb`/`__oailb` `Set-Cookie` lines are still on the HTTP response.
- **WebSocket transport no longer puts `x-codex-turn-state` on the 101 upgrade
  response.** It arrives instead inside a `codex.response.metadata` WS message
  under `headers["x-codex-turn-state"]` (780-length value), ahead of
  `response.created`. The pair cookies are still minted on the 101
  `Set-Cookie` lines, and `response.created.response.model` is unchanged.

## What the plugin does with this

A 292 enters the store from one of two places, and neither of them is the
incoming request:

- **The offline probe** calls `chatgpt.com/backend-api/codex/responses` directly
  as one account, so the upstream mints a state the probe then keeps. CPA is not
  involved and none of its state is touched.
- **The response hooks** read the state the upstream mints for ordinary business
  traffic. This costs nothing, because the request was going out anyway, and it
  is self-limiting: once a bucket holds a template the request hook injects it,
  the upstream stops minting for that bucket, and this side goes quiet until the
  template lapses.

A 292 arriving on an incoming **request** is a different thing and is not
stored: its provenance is unknown — a replay, or another session's state the
client happened to send. That path (`harvest_inband`) is forced off for the
business role.

On the way out, `request.intercept_after` replaces a 312 with the bucket's live
292 (or, under `inject_mode: always`, adds one to a request that carried none)
and merges the account's pooled `__cflb`/`__oailb` into the request's Cookie
header — stored names win over same-named client pairs, everything else the
client sent is preserved. Expiry is computed from the token's embedded Fernet
timestamp (`fernetIssuedAt` in `go/main.go`), so a template harvested late in
its life is not mistaken for a fresh one.

The plugin never fabricates a value, and never crosses the account or model
boundary.
