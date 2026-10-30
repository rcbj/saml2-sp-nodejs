# Handling CAEP and RISC events

`SignalsReceiver` hands every verified Shared Signals event to the handlers you register, one event type at a time. This page lists every event type of OpenID CAEP 1.0 and OpenID RISC 1.0: what each means, what it carries, what the receiver does with it by default, and how to handle it yourself. The [reference](../README.md#shared-signals-caep-and-risc) covers starting the receiver.

* TOC
{:toc}

## Registering a handler

```ts
import { EVENT, SignalsReceiver, type SignalEvent } from 'saml2-sp-nodejs';

const signals = new SignalsReceiver({ transmitter, tls, onEndSessions });

signals.on(EVENT.credentialChange, async (event: SignalEvent) => {
  await audit.write('credential-change', event.subject.person, event.payload);
});

// Every event, of any type, after the type's own handlers:
signals.on('*', (event) => metrics.count(event.type));

await signals.start();
```

- **`on(type, handler)`** adds a handler for one event type URI. Use the `EVENT` constants rather than typing URIs. Several handlers may be registered for one type; they run in the order they were added, then the `'*'` handlers.
- **Handlers run after the SET is verified**: signature, `iss`, `aud`, `typ`, `jti`. A handler never sees a forged or misaddressed event.
- **A handler may be async.** The receiver awaits it before handling the next event, and acknowledges the SET only after every handler has run.
- **A handler that throws is logged, and the SET is still acknowledged.** The SET was valid; the failure is the application's. So make a handler that must not lose an event durable itself (write it to a queue or table first).
- **Ending sessions is not a handler's job.** For the types in `endOn`, the receiver calls `onEndSessions(localIds, event)` first, then the handlers, with `event.ended` true. A handler reads `event.sessions` to learn which local sessions the event named.

### What a handler receives

```ts
interface SignalEvent {
  type: string;                       // the event type URI, e.g. EVENT.sessionRevoked
  payload: Record<string, unknown>;   // the event's own members (below)
  subject: {
    person?: string;                  // an iss_sub subject's sub, e.g. 'urn:uuid:…'
    email?: string;                   // an email subject
    idpSession?: string;              // a complex subject's session: the SAML SessionIndex
  };
  sessions: string[];                 // the local sessions it names (from track())
  ended: boolean;                     // whether the receiver ended them
  jti: string;                        // the SET's id
  iat?: number;                       // when the SET was issued
  txn?: string;                       // the transaction id, when the transmitter sent one
}
```

`event.sessions` holds the local sessions the event names:
- **A session event with an IdP session** (CAEP's complex subject, `user` plus `session`) names only the local sessions started from that IdP session.
- **Any other event** names every local session of the person: matched by `subject.person` against the subject attribute `track()` recorded, then by `subject.email`.

### Choosing which events to receive, and which end sessions

```ts
import { CAEP_EVENTS, EVENT, RISC_EVENTS, SignalsReceiver } from 'saml2-sp-nodejs';

new SignalsReceiver({
  transmitter, tls, onEndSessions,
  // Ask for every CAEP and RISC type (the default asks for the ten in DEFAULT_EVENTS_REQUESTED).
  eventsRequested: [...CAEP_EVENTS, ...RISC_EVENTS],
  // End sessions on these (the default is DEFAULT_ENDING_EVENTS, five types).
  endOn: [EVENT.sessionRevoked, EVENT.accountDisabled, EVENT.accountPurged,
          EVENT.credentialCompromise, EVENT.sessionsRevoked, EVENT.riskLevelChange],
});
```

- **`eventsRequested` is what the stream asks for when it is created.** The transmitter delivers what it supports of that (`receiver.stream.events_delivered`). An existing stream keeps what it asked for originally. To change it, delete the stream at the transmitter and let `start()` create a new one.
- **`endOn` only decides which events end sessions.** Every delivered event reaches its handlers either way.
- **To end sessions only on some events of a type**, leave that type out of `endOn` and decide in a handler. For example, end the person's sessions on a `risk-level-change` only when its level is HIGH; see that event's section.

### Members every CAEP event may carry

CAEP 1.0 section 2 gives every CAEP event four optional members:

| Member | |
|---|---|
| `event_timestamp` | When the event happened at the transmitter, in seconds (NumericDate). |
| `initiating_entity` | Who caused it: `admin`, `user`, `policy` or `system`. |
| `reason_admin` | Why, for an administrator: a language map such as `{ "en": "…" }`. |
| `reason_user` | Why, for the person: a language map. Fit to show to them. |

In the event tables below, *Default* is what the receiver does with that type when you change nothing: whether the type is in `DEFAULT_EVENTS_REQUESTED`, and whether it is in `DEFAULT_ENDING_EVENTS`.

## CAEP events (about sessions)

### `session-revoked`: the person's session at the identity provider ended

| | |
|---|---|
| Constant | `EVENT.sessionRevoked` |
| Subject | complex: `user` (`iss_sub`) and `session` (`opaque`, the SAML `SessionIndex`) |
| Members | the four common ones |
| Default | requested; **ends the local sessions started from that IdP session** |

iya-sts sends it when the person signs out, a sign-on session expires, an administrator ends one (Monitoring → Sessions, a global logout), or a disable ends everything.

```ts
signals.on(EVENT.sessionRevoked, (event) => {
  // The sessions are already ended (onEndSessions ran). Record why, for the person's next sign-in page.
  const why = (event.payload.reason_user as Record<string, string> | undefined)?.en;
  for (const id of event.sessions) signedOutReasons.set(id, why ?? 'Signed out at the identity provider.');
});
```

### `credential-change`: a credential was created, changed, revoked or deleted

| | |
|---|---|
| Constant | `EVENT.credentialChange` |
| Subject | complex: `user` |
| Members | `credential_type` (required), e.g. `password`, `pin`, `x509`, `fido2-platform`, `fido2-roaming`, `fido-u2f`, `verifiable-credential`, `phone-voice`, `phone-sms`, `app`, or a URI of the transmitter's own (iya-sts: `urn:iya:sts:credential-type:kerberos-key`); `change_type` (required): `create`, `revoke`, `update` or `delete`; `friendly_name`; `x509_issuer`, `x509_serial`; `fido2_aaguid`; the four common ones |
| Default | requested; ends nothing |

```ts
signals.on(EVENT.credentialChange, async (event) => {
  const { credential_type, change_type } = event.payload as { credential_type: string; change_type: string };
  // A password changed elsewhere: ask the person to sign in again here too, but not mid-request.
  if (credential_type === 'password' && change_type !== 'create') {
    for (const id of event.sessions) await sessions.markForReauthentication(id);
  }
});
```

### `token-claims-change`: claims in the person's tokens or assertions changed

| | |
|---|---|
| Constant | `EVENT.tokenClaimsChange` |
| Subject | complex: `user` |
| Members | `claims` (required): an object of the changed claims and their new values; the four common ones |
| Default | requested; ends nothing |

A SAML session holds the attributes from sign-in. This tells you they are out of date, for example a group membership or a role.

```ts
signals.on(EVENT.tokenClaimsChange, async (event) => {
  const claims = event.payload.claims as Record<string, unknown>;
  for (const id of event.sessions) await sessions.update(id, { staleAttributes: Object.keys(claims) });
});
```

### `assurance-level-change`: the authentication's assurance level went up or down

| | |
|---|---|
| Constant | `EVENT.assuranceLevelChange` |
| Subject | complex: `user` and `session` |
| Members | `namespace` (required; iya-sts: `urn:sts:acr`); `current_level` (required); `previous_level`; `change_direction`: `increase` or `decrease`; the four common ones |
| Default | requested; ends nothing |

```ts
signals.on(EVENT.assuranceLevelChange, async (event) => {
  // Remember the level, so a page that needs multi-factor can ask for a step-up when it fell.
  for (const id of event.sessions) await sessions.update(id, { acr: event.payload.current_level });
});
```

### `device-compliance-change`: the device's compliance status changed

| | |
|---|---|
| Constant | `EVENT.deviceComplianceChange` |
| Subject | complex: `user` and `device` (iya-sts: `iss_sub` naming the registered device) |
| Members | `current_status` (required) and `previous_status` (required): `compliant` or `not-compliant`; the four common ones |
| Default | not requested (add it to `eventsRequested`) |

```ts
signals.on(EVENT.deviceComplianceChange, async (event) => {
  // Not ended by default: a non-compliant device may still read, but not write.
  if (event.payload.current_status === 'not-compliant') {
    for (const id of event.sessions) await sessions.update(id, { readOnly: true });
  }
});
```

### `session-established`: the person signed in at the identity provider

| | |
|---|---|
| Constant | `EVENT.sessionEstablished` |
| Subject | complex: `user` and `session` |
| Members | `fp_ua` (a fingerprint of the user agent); `acr`; `amr`; `ext_id`; the four common ones |
| Default | not requested |

It names a new IdP session, so no local session is started from it yet and `event.sessions` is the person's other local sessions. It suits auditing and anomaly detection.

```ts
signals.on(EVENT.sessionEstablished, (event) => {
  audit.write('idp-sign-in', event.subject.person, { acr: event.payload.acr, amr: event.payload.amr });
});
```

### `session-presented`: an existing IdP session was used again (single sign-on)

| | |
|---|---|
| Constant | `EVENT.sessionPresented` |
| Subject | complex: `user` and `session` |
| Members | `fp_ua`; `ext_id`; the four common ones |
| Default | not requested |

```ts
signals.on(EVENT.sessionPresented, (event) => {
  // Keep a local session alive while its IdP session is in use elsewhere.
  for (const id of event.sessions) sessions.touch(id);
});
```

### `risk-level-change`: the transmitter's risk assessment changed

| | |
|---|---|
| Constant | `EVENT.riskLevelChange` |
| Subject | complex: `user` (or the `device`, `session`… the `principal` names) |
| Members | `risk_reason` (required); `principal` (required): `USER`, `DEVICE`, `SESSION`, `TENANT`, `ORG_UNIT` or `GROUP`; `current_level` (required): `LOW`, `MEDIUM` or `HIGH`; `previous_level`; the four common ones |
| Default | not requested |

```ts
signals.on(EVENT.riskLevelChange, async (event) => {
  const { current_level, principal } = event.payload as { current_level: string; principal: string };
  // End the person's sessions only when their risk is HIGH, rather than on every change.
  if (principal === 'USER' && current_level === 'HIGH' && event.sessions.length) {
    await endMySessions(event.sessions, 'Your account was flagged as high risk.');
  }
});
```

## RISC events (about accounts)

RISC subjects are plain, not complex. iya-sts names the account as `iss_sub` with `sub` set to `urn:uuid:…` (`risc.subjectFormat`). The identifier events use `email` or `phone_number`. So a RISC event names every local session of the person.

### `account-disabled`: the account was disabled

| | |
|---|---|
| Constant | `EVENT.accountDisabled` |
| Members | `reason` (optional): `hijacking` or `bulk-account` |
| Default | requested; **ends every local session of the person** |

```ts
signals.on(EVENT.accountDisabled, async (event) => {
  // Sessions are already ended. Also refuse new local sign-ins until account-enabled arrives.
  await accounts.block(event.subject.person!, event.payload.reason ?? 'disabled at the identity provider');
});
```

### `account-enabled`: the account was enabled again

| | |
|---|---|
| Constant | `EVENT.accountEnabled` |
| Members | none |
| Default | requested; ends nothing |

```ts
signals.on(EVENT.accountEnabled, (event) => accounts.unblock(event.subject.person!));
```

### `account-purged`: the account was deleted

| | |
|---|---|
| Constant | `EVENT.accountPurged` |
| Members | none |
| Default | requested; **ends every local session of the person** |

```ts
signals.on(EVENT.accountPurged, async (event) => {
  // Remove or anonymise what the application keeps about the person.
  await profiles.deleteBySubject(event.subject.person!);
});
```

### `credential-compromise`: a credential is known or suspected to be compromised

| | |
|---|---|
| Constant | `EVENT.credentialCompromise` |
| Members | `credential_type` (required, CAEP's list); `event_timestamp`; `reason_admin`; `reason_user` |
| Default | requested; **ends every local session of the person** |

```ts
signals.on(EVENT.credentialCompromise, async (event) => {
  await security.alert(`compromised ${event.payload.credential_type} for ${event.subject.person}`);
});
```

### `account-credential-change-required`: the person must change a credential

| | |
|---|---|
| Constant | `EVENT.accountCredentialChangeRequired` |
| Members | none |
| Default | requested; ends nothing |

```ts
signals.on(EVENT.accountCredentialChangeRequired, async (event) => {
  // Send the person to the identity provider's password change on their next page.
  for (const id of event.sessions) await sessions.update(id, { mustChangeCredential: true });
});
```

### `identifier-changed`: an identifier (email address, phone number) changed

| | |
|---|---|
| Constant | `EVENT.identifierChanged` |
| Subject | the OLD identifier: `email` or `phone_number` |
| Members | `new-value` (optional; **note the hyphen**, the only one in SSF), absent when the identifier was removed |
| Default | not requested |

```ts
signals.on(EVENT.identifierChanged, async (event) => {
  // The subject is the old address; the receiver matched sessions by email through it.
  if (event.subject.email) await profiles.renameEmail(event.subject.email, event.payload['new-value'] as string | undefined);
});
```

### `identifier-recycled`: an identifier now belongs to a different account

| | |
|---|---|
| Constant | `EVENT.identifierRecycled` |
| Subject | the identifier: `email` or `phone_number` |
| Members | none |
| Default | not requested |

```ts
signals.on(EVENT.identifierRecycled, async (event) => {
  // Anything keyed by this address belonged to someone else: unlink it.
  if (event.subject.email) await profiles.unlinkEmail(event.subject.email);
});
```

### `recovery-activated`: account recovery was started

| | |
|---|---|
| Constant | `EVENT.recoveryActivated` |
| Members | none |
| Default | not requested |

```ts
signals.on(EVENT.recoveryActivated, (event) => security.notice(`recovery started for ${event.subject.person}`));
```

### `recovery-information-changed`: recovery information (address, codes) changed

| | |
|---|---|
| Constant | `EVENT.recoveryInformationChanged` |
| Members | none |
| Default | not requested |

```ts
signals.on(EVENT.recoveryInformationChanged, (event) => audit.write('recovery-info-changed', event.subject.person));
```

### `opt-in`, `opt-out-initiated`, `opt-out-cancelled`, `opt-out-effective`: the person's participation in event exchange

| | |
|---|---|
| Constants | `EVENT.optIn`, `EVENT.optOutInitiated`, `EVENT.optOutCancelled`, `EVENT.optOutEffective` |
| Members | none |
| Default | not requested |

These are RISC 1.0 section 2.8's states. After `opt-out-effective` the transmitter sends no more events about that account until `opt-in`. An application that relies on signals should know when they stop.

```ts
signals.on(EVENT.optOutEffective, (event) => accounts.setSignals(event.subject.person!, false));
signals.on(EVENT.optIn, (event) => accounts.setSignals(event.subject.person!, true));
```

### `sessions-revoked` (deprecated): every session of the account was revoked

| | |
|---|---|
| Constant | `EVENT.sessionsRevoked` |
| Members | none |
| Default | requested; **ends every local session of the person** |

RISC 1.0 deprecates it in favour of CAEP's `session-revoked`, but transmitters still send it. iya-sts sends it by hand and on an emergency signing-key rotation.

## The stream's own events

| Constant | | |
|---|---|---|
| `EVENT.verification` | SSF 1.0 `verification` | The answer to `receiver.verify(state)`; `payload.state` is what you passed. It names no person. |
| `EVENT.streamUpdated` | SSF 1.0 `stream-updated` | The stream's status changed; `payload.status` is `enabled`, `paused` or `disabled`, with `reason`. |

Neither is in `eventsRequested`: SSF delivers them anyway. Neither ends a session.

```ts
signals.on(EVENT.streamUpdated, (event) => {
  if (event.payload.status !== 'enabled') ops.alert(`the signals stream is ${event.payload.status}: ${event.payload.reason ?? ''}`);
});
```
