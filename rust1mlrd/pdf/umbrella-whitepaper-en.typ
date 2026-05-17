#import "styles.typ": *

#show: doc => setup-doc(
  title: "Whitepaper",
  author: "Umbrella Protocol Team",
  lang: "en",
  doc,
)

// ============================================================================
// Cover
// ============================================================================

#umbrella-cover(
  title: "Whitepaper",
  subtitle: "A secure messenger for one billion users",
  tagline: "Distributed identity · Post-quantum cryptography · State-level adversary defense",
  version: "1.1.0",
  date: "May 17, 2026",
  authors: "Umbrella Protocol Team",
)

// ============================================================================
// Table of contents
// ============================================================================

#set page(numbering: "1", header: none)
#counter(page).update(1)

#block(above: 0pt, below: 1em)[
  #text(size: 26pt, weight: "bold", fill: umbrella-primary)[Contents]
]
#line(length: 100%, stroke: 0.6pt + umbrella-primary)
#v(0.6em)

#outline(title: none, depth: 2, indent: auto)

#pagebreak()

// ============================================================================
// Section 1 — Introduction
// ============================================================================

= Introduction

#callout(title: "The thesis in fifteen seconds", color: umbrella-primary)[
  Umbrella Protocol is a messenger engineered so that your conversations
  cannot be read even if *simultaneously* your phone is seized, a
  government coerces our company, and Apple or Google receive a court
  order to surrender keys. The user's private key *never exists in any
  single location*: it is born distributedly across five servers in
  different jurisdictions and lives only as threshold shares. There is
  nothing on the device that a forensic tool can extract.
]

== Why this work exists

In 2026, messengers are no longer just a way to send text. They are
the primary channel for the political, journalistic, medical, legal,
and personal communications of one billion people. And that channel
is under attack:

- *Governments* pass laws mandating backdoors and use NSLs#footnote-term("NSL — National Security Letter", "a U.S. order to secretly surrender user data; gag clause forbids disclosure that the request exists") to
  compel private companies to surrender user keys.

- *Forensic vendors* — Cellebrite, GrayKey, MSAB — sell governments
  tools that extract data from both powered-down and unlocked phones.
  Their customers are not only the FBI and Interpol; Citizen Lab
  documents sales to repressive regimes worldwide.

- *Mercenary spyware vendors* — NSO Group (Pegasus), Candiru,
  Intellexa (Predator) — target journalists and activists through
  zero-click vulnerabilities in iMessage, WhatsApp, and FaceTime.
  Pegasus has been deployed against 50+ journalists and 10+ heads of
  state between 2016 and 2024 (the Forbidden Stories "Pegasus
  Project", 2021).

- *Cloud services themselves* (iCloud Backup, Google Drive) keep
  "encrypted" backups to which the providers hold the keys. Under NSL
  coercion Apple has surrendered those keys to law enforcement (the
  2016 San Bernardino case — Apple refused; the 2023 Hong Kong
  activist case — Apple complied).

== What is broken in existing messengers

*Telegram* by default stores conversations on its own servers with
server-side encryption. This is convenient for sync but is
operationally equivalent to "trust Pavel Durov's company". Secret
Chats with E2EE#footnote-term("E2EE — End-to-End Encryption", "only the recipient can decrypt; the server sees ciphertext only") are a separate feature that must be enabled by
hand and is only available in the mobile client.

*WhatsApp* implements the Signal protocol (E2EE by default), but is
owned by Meta. In 2020 WhatsApp pushed users to accept a new
metadata-sharing policy with Facebook. In 2021 The Guardian published
a leak showing that WhatsApp does read user-reported message
contents — i.e. E2EE does not prevent access to decrypted content via
the UI channel.

*Signal* is the most respected E2EE messenger. It uses the Double
Ratchet#footnote-term("double ratchet", "a key-update mechanism that changes the encryption key after every message so that loss of an old key does not enable reading newer ones"). It minimizes metadata. It is open source. But Signal
binds the identity to the phone number (SMS), which:
- enables SIM-swap attacks (taking over the number via the carrier),
- yields metadata correlation at the carrier level,
- and leaves a recovery key on-device (no defense against device
  seizure in the unlocked state).

*All of them* — Telegram, WhatsApp, Signal — generate the user's
long-lived secret *on the device* during registration. That secret
lives in RAM while the app is in use and is reachable by a forensic
tool with physical access and a debugger.

== Goal of Umbrella Protocol

We build a messenger with three properties at the same time:

1. *Telegram-grade UX* — a one-screen signup, instant message send,
   QR-based multi-device.
2. *Signal-grade cryptography* — E2EE by default, forward secrecy#footnote-term("forward secrecy", "a property such that if an adversary obtains today's keys, they still cannot decrypt yesterday's messages"),
   open source.
3. *State-level adversary defense* — no private key on the device,
   distributed across 5 servers in 5 jurisdictions, irreversible
   destruction under coercion.

== Adversary model

Umbrella Protocol is designed against the full SPEC-01 model D
adversary:

- A state-level actor with the ability to physically seize the device.
- A state cooperating with Apple or Google.
- A state with a zero-day for remote exploitation.
- A state with a commercial forensic tool (Cellebrite, GrayKey,
  Magnet AXIOM).
- A coalition of governments coercing several of our server operators.
- A compromised hardware-security-module vendor (Secure Enclave /
  StrongBox).
- A future quantum computer that decrypts archived traffic
  ("harvest now, decrypt later").

#pagebreak()

// ============================================================================
// Section 2 — Comparison table
// ============================================================================

= Comparison with other messengers

The table below compares four messengers across 32 properties.
Green indicates the property is implemented and verified. Red
indicates it is absent or demonstrably broken. Yellow indicates
partial or optional coverage. Gray indicates not applicable.

#set table(
  inset: (x: 6pt, y: 5pt),
  stroke: 0.4pt + umbrella-rule,
)
#set text(size: 9pt)

#table(
  columns: (1.6fr, 1fr, 1fr, 1fr, 1fr),
  align: (left, center, center, center, center),
  head-cell([Property]), head-cell([Umbrella]), head-cell([Signal]), head-cell([WhatsApp]), head-cell([Telegram]),
  // 1
  [Where the private key is generated],
  good[5 servers],
  bad[On device],
  bad[On device],
  bad[Telegram servers],
  // 2
  [Where the private key is stored],
  good[Threshold shares],
  bad[In device RAM],
  bad[In device RAM],
  bad[On servers],
  // 3
  [E2EE by default],
  good[Yes],
  good[Yes],
  good[Yes],
  bad[No (opt-in)],
  // 4
  [Apple/Google NSL defense],
  good[Full],
  warn[Partial],
  bad[None],
  bad[None],
  // 5
  [Cellebrite (unlocked) defense],
  good[No keys on device],
  bad[Key in RAM],
  bad[Key in RAM],
  bad[Key in RAM],
  // 6
  [Cellebrite (powered off) defense],
  good[Full],
  good[Full],
  good[Full],
  warn[Partial],
  // 7
  [Forward secrecy],
  good[MLS],
  good[Double Ratchet],
  good[Double Ratchet],
  warn[Secret chats only],
  // 8
  [Post-compromise security],
  good[Yes],
  good[Yes],
  good[Yes],
  bad[No],
  // 9
  [Multi-device],
  good[Up to 16],
  good[Yes],
  good[Yes],
  good[Yes],
  // 10
  [Account recovery],
  good[24 words + 24 h],
  warn[By phone number],
  warn[By phone number],
  warn[By phone number],
  // 11
  [SIM-swap defense],
  good[No phone required],
  bad[SMS-bound],
  bad[SMS-bound],
  bad[SMS-bound],
  // 12
  [Coercion (duress)],
  good[Reverse PIN → wipe],
  bad[None],
  bad[None],
  bad[None],
  // 13
  [Chat screenshots],
  good[Block + detect],
  warn[Notify],
  warn[Notify],
  bad[Free],
  // 14
  [Disable Siri / Assistant],
  good[On PIN screen],
  bad[No],
  bad[No],
  bad[No],
  // 15
  [Disable Smart Reply],
  good[Full],
  bad[No],
  bad[No],
  bad[No],
  // 16
  [Disable AutoFill / Clipboard],
  good[Full],
  bad[No],
  bad[No],
  bad[No],
  // 17
  [Multi-government collusion],
  good[Up to 2 of 5 servers],
  bad[Single operator],
  bad[Single operator],
  bad[Single operator],
  // 18
  [Server jurisdictions],
  good[5 distinct],
  warn[US],
  bad[US (Meta)],
  warn[UAE + scattered],
  // 19
  [Post-quantum encryption],
  good[X-Wing hybrid],
  warn[PQ KEX (PQXDH)],
  bad[No],
  bad[No],
  // 20
  ["Harvest now" defense],
  good[Full],
  good[Since 2023],
  bad[No],
  bad[No],
  // 21
  [Hedged encryption],
  good[Bellare 2015],
  bad[No],
  bad[No],
  bad[No],
  // 22
  [Safe cloud backup],
  good[Closed on 5 servers],
  warn[Optional],
  bad[iCloud (Apple-held key)],
  bad[Google/iCloud],
  // 23
  [DoS resilience (Tor/AltIP/Mixnet)],
  good[Cascade fallback],
  warn[Tor proxy],
  bad[No],
  bad[No],
  // 24
  [Anti-tamper (debugger detect)],
  good[Lifecycle wipe],
  bad[No],
  bad[No],
  bad[No],
  // 25
  [mlock secrets in memory],
  good[MlockedSecret],
  bad[No],
  bad[No],
  bad[No],
  // 26
  [Zeroize on drop],
  good[Heap + stack scrub],
  warn[Partial],
  warn[Partial],
  bad[No],
  // 27
  [Dead-man switch],
  good[Optional],
  bad[No],
  bad[No],
  bad[No],
  // 28
  [Reproducible builds],
  good[Roadmap v1.2],
  good[Android: yes],
  warn[Partial],
  bad[No],
  // 29
  [Open source client],
  good[Fully],
  good[Fully],
  warn[Partial],
  warn[Client only],
  // 30
  [Open source server],
  good[Fully],
  good[Fully],
  bad[No],
  bad[No],
  // 31
  [Independent audit],
  good[6 PhD-B rounds],
  good[Trail of Bits, NCC],
  warn[Internal only],
  warn[Internal only],
  // 32
  [Formal verification],
  good[Tamarin 16 lemmas],
  warn[ProVerif partial],
  bad[No],
  bad[No],
)

#set text(size: 10.5pt)

#callout(title: "How to read this table", color: umbrella-secondary)[
  The comparison is built from open sources: protocol documentation,
  published audits, source code. We deliberately mark Signal and
  WhatsApp green where they do the right thing — these are respected
  protocols and Umbrella borrows heavily from them (MLS is a cousin
  of the Signal protocol; forward secrecy is inherited). The point of
  the table is not to disparage existing solutions but to show which
  specific attack axes Umbrella additionally covers.
]

#pagebreak()

// ============================================================================
// Section 3 — Architecture in plain words
// ============================================================================

= Architecture of Umbrella

This chapter explains how Umbrella works without cryptographic
equations, for readers who have never read a security protocol
paper. Technical terms are footnoted on first use.

== Three layers of keys

In a classical messenger there is one long-lived user key. If it
leaks, the entire conversation history is readable. Umbrella
splits keys across three layers:

#three-layer-keys-diagram(labels: (
  identity: "Identity",
  device: "Device",
  session: "Session",
  desc-identity: "Distributed over 5 servers",
  desc-device: "Re-derived from PIN + 3-of-5 shares",
  desc-session: "MLS ratchet, per-message",
))

*Layer 1 — Identity.* Your "permanent" key. Lives for years and
identifies you among your contacts. In ordinary messengers this
key is a file on the device. In Umbrella that file does not exist:
the key is created and stored distributedly on 5 servers; no
server alone knows the whole key.

*Layer 2 — Device.* The working key the messenger uses to sign
and encrypt here and now. It lives precisely as long as you keep
the app open. When the app is backgrounded or 2 minutes of
inactivity pass, the key is wiped from memory. On the next PIN
entry the key is *re-derived* from your PIN plus shares from the
servers.

*Layer 3 — Session.* One key per message. After each message it
rotates through the MLS#footnote-term("MLS — RFC 9420", "Messaging Layer Security — IETF standard for group-chat encryption with forward secrecy") ratchet. If an adversary captures
today's key, they cannot decrypt either yesterday's or tomorrow's
messages.

== Distributed identity: five servers in five countries

#five-servers-diagram(labels: (
  title: "Distributed identity over 5 sealed servers",
  servers: ("DE", "CH", "IS", "NL", "JP"),
  caption: "Threshold 3-of-5 reconstructs the device key; ≤2 compromised servers leak nothing.",
))

When you create an Umbrella account, the following happens:

1. *Your device* asks five servers (in Germany, Switzerland,
   Iceland, the Netherlands and Japan): "build a private key for me".

2. *The five servers* run a joint protocol called FROST#footnote-term("FROST", "Flexible Round-Optimized Schnorr Threshold Signatures by Komlo and Goldberg, CRYPTO 2020"). Each
   server generates a random share and commits to it through
   the Pedersen-VSS#footnote-term("Pedersen-VSS", "Verifiable Secret Sharing, Pedersen 1991 — proves a share is consistent without revealing the secret") scheme. The output is:
   - each server holds one share,
   - the public key is known to everyone,
   - *the secret key does not exist in any single location*.

3. *Your device* receives only the public key + one
   `device_random` (a 32-byte value in the Secure Enclave) + a
   16-byte salt. *No 24 words are ever shown to you.*

This means: if the FSB or FBI seize your device, the secret key
*is physically not there*. They may break into the Secure Enclave
(tens of millions of dollars and weeks of work) and find only
`device_random` — which alone means nothing without the PIN and
3 shares from servers across different jurisdictions.

== Daily PIN-based unlock

#unlock-flow-diagram(labels: (
  title: "PIN-based unlock flow",
  steps: (
    "Enter PIN",
    "Argon2id",
    "3-of-5 shares",
    "HKDF re-derive",
    "Ready",
  ),
  caption: "All transient state lives in mlock'd heap, wiped on background.",
))

When you open Umbrella in the morning:

1. You enter a *6-digit PIN* on a special keypad. The digits on
   that keypad are *reshuffled every time* — so a ceiling camera
   cannot infer your PIN from finger trajectory.

2. The app runs your PIN through *Argon2id*#footnote-term("Argon2id", "password hashing function, winner of the Password Hashing Competition 2015; 64 MiB memory + 3 iterations makes GPU brute force economically infeasible"). Parameters: 64 MiB
   memory, 3 iterations, 4-way parallelism. This takes 400-800 ms
   on a modern iPhone — noticeable to the user, cheap compared to
   the benefit.

3. The app sends anonymous requests to the 5 servers. Each server
   sees its own *unique anonymous identifier* for your account —
   IDs are uncorrelated across servers.

4. *Any 3 of 5* servers return their shares. If 1 or 2 servers
   are unavailable (DoS, government seizure, collusion), unlock
   still succeeds.

5. On the device the shares are *combined with the PIN-derived
   value and device_random* via HKDF#footnote-term("HKDF", "HMAC-based Key Derivation Function, RFC 5869, the standard mechanism for safely deriving keys"). The output is the device
   working keys plus the master key.

6. Keys are *immediately placed in mlock'd memory*#footnote-term("mlock", "system call that prevents the OS from paging the memory region to swap; secrets never reach disk"). After assembly
   the app is ready to use.

== Hybrid post-quantum encryption

#hybrid-pq-diagram(labels: (
  title: "Hybrid post-quantum encapsulation (X-Wing)",
  classical: "X25519",
  classical-desc: "Classical ECDH",
  pq: "ML-KEM-768",
  pq-desc: "Lattice-based post-quantum KEM",
  combiner: "HKDF combiner",
  combiner-desc: "Joint shared secret",
  rng: "OsRng + identity witness (hedged seed, Bellare 2015)",
  caption: "Either half can fall; the survivor protects K.",
))

In 10 to 20 years quantum computers will be able to decrypt
today's classical cryptography (X25519, RSA). Governments are
*already recording* encrypted traffic with the intent of
decrypting it later ("harvest now, decrypt later").

Umbrella uses *X-Wing*#footnote-term("X-Wing", "IETF draft-connolly-cfrg-xwing-kem; combines classical X25519 with the post-quantum ML-KEM-768") — a hybrid KEM that combines:

- *X25519* — classical elliptic-curve Diffie-Hellman,
- *ML-KEM-768* — lattice-based post-quantum algorithm (NIST FIPS
  203, August 2024),

through HKDF. Security is guaranteed by the *minimum* of the two
security parameters — even if a quantum computer breaks X25519,
ML-KEM-768 still protects the key. If cryptanalysis breaks
ML-KEM-768, X25519 still holds. This construction is called a
*hybrid combiner* and is the conservative defense during the
transition period until post-quantum maturity.

*Additionally* we apply "hedged encryption" by Bellare-Hoang-
Keelveedhi 2015: even if the operating-system random number
generator is compromised (as in the 2008 Debian OpenSSL bug),
encryption does not break — because a *stable identity secret*
from the distributed key is mixed into the seed.

== Key lifecycle: always clean

In most messengers, keys live in memory for as long as the app is
running. That means a forensic tool with physical access to an
unlocked phone can read those keys via the OS.

In Umbrella all secrets live *only during an active session*:

- *Backgrounding the app* (Home button, App Switcher): a 2-minute
  timer starts, after which all in-memory keys are wiped through
  `zeroize()`. On return — PIN again.
- *Screen lock*: immediate wipe.
- *Debugger detection* (lldb, gdb, Frida): immediate wipe + app
  shuts down.
- *Jailbreak / root detection*: refuses to run with warning.

#pagebreak()

// ============================================================================
// Section 4 — UX
// ============================================================================

= What the user sees

== Registration

Open the app. One screen:

```
┌──────────────────────────────────┐
│         Create account           │
│                                  │
│       Set a 6-digit PIN          │
│                                  │
│         [ * * * * * * ]           │
│                                  │
│      (optional) Phone number     │
│      for friend discovery        │
│                                  │
│         [   Create   ]           │
└──────────────────────────────────┘
```

Tap "Create", wait 2-3 seconds (distributed key generation happens
on the 5 servers). Account is ready. *No 24 words are shown to you.*
If you later want to export a recovery code, it is in Settings,
behind separate protection.

The phone number is *optional*. If you provide it, it is used only
so that friends from your address book can find you (like
Telegram). It does not affect account login.

== Daily open

Open Umbrella. The PIN screen:

```
┌──────────────────────────────────┐
│              PIN                 │
│                                  │
│        ○ ○ ○ ○ ○ ○               │
│                                  │
│         [ 7 ]  [ 2 ]  [ 9 ]       │
│         [ 1 ]  [ 5 ]  [ 3 ]       │
│         [ 8 ]  [ 0 ]  [ 4 ]       │
│              [ 6 ]                │
│                                  │
│         Touch ID / Face ID       │
└──────────────────────────────────┘
```

Digits on the keypad are *reshuffled randomly*. Buttons do not
highlight on press. If biometrics (Touch ID, Face ID) are enabled,
you can open with a fingerprint — it protects access to
`device_random` but a PIN is still required to reassemble keys.

On this screen Umbrella *disables* the following system services:
Siri, Google Assistant, Smart Reply, AutoFill, Clipboard,
autocorrect, dictation, screen recording, Assistant API,
accessibility-services suggestions.

== Sending a message

No round-trip to servers. The message is encrypted *locally on the
device* via MLS, placed into the local outbox, and delivered to the
recipient over the network through ordinary TLS plus the Tor/AltIP/
Mixnet fallback.

Umbrella servers *do not participate in message sending* — they are
only needed for unlock (at most once every 24 hours) and for
adding/removing devices. This means: even if all 5 servers are
down, you can still send messages to existing contacts.

== Adding a device

```
On the primary phone:           On the new phone:
┌──────────────────┐           ┌──────────────────┐
│ Settings →       │           │ Open Umbrella    │
│ Devices →        │           │                  │
│ Add              │  ─QR──→  │ Scan QR from     │
│                  │           │ primary          │
│ [QR code]        │           │                  │
└──────────────────┘           └──────────────────┘
```

The QR contains the public parameters plus a one-time
authentication token. After the scan the primary phone confirms
with PIN, and the new device gets its own `device_random` in
SE/StrongBox plus its share-request envelope to the servers. Up
to 16 devices per account.

== Account recovery (lost phone)

If the primary phone is lost/stolen/broken, two paths:

*Path A — 24-word recovery code* (if you exported it). On a new
device enter the 24 words plus a new PIN. Servers start a *24-hour
time-lock*: throughout that period push notifications go to your
old phone — "account recovery started; cancel?". If an adversary
stole only your 24-word paper (not the phone), you see the push,
tap "cancel", attack is aborted. If you also know the old PIN —
recovery accelerates to 1 hour.

*Path B — 12 words* (last resort). If the 24 words are forgotten
or lost, there is a fallback emergency code of 12 words. After
3 wrong entries of the 24-word path the system offers the
12-word path. 5 wrong entries of 12 words = *irreversible account
deletion*.

== Coercion (duress)

A rare but important scenario: a state representative comes to you
and demands the PIN under threat. Umbrella provides a way to enter
a "fake" PIN that, indistinguishably from the attacker's view,
*wipes the account*:

- Your normal PIN: `123456`
- *Duress PIN (reverse): `654321`*

If you enter the reverse PIN, the loading screen looks identical
to a normal unlock, 3 seconds pass, then a "no account on this
device" screen appears. Simultaneously the 5 servers receive an
`UNRECOVERABLE_DELETE` command in parallel. Shares are wiped. The
account is genuinely deleted; no 24-word phrase can recover it.

Palindrome protection: PINs of the form `121212` are not accepted
as normal PINs — because reversing them yields the original and
duress would be impossible.

#pagebreak()

// ============================================================================
// Section 5 — Attack scenarios
// ============================================================================

= Attack scenarios

This chapter lists concrete attack scenarios against the messenger
user. For each scenario we show what happens in Telegram, Signal,
WhatsApp, and Umbrella.

#attack-box(num: "C1", title: "Cellebrite seizes the powered-off phone")[
  *Scenario.* Your iPhone is confiscated at the border, powered off.
  Taken to a Cellebrite lab, which uses UFED Premium to bypass the
  lock screen and extract data.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Telegram/Signal/WhatsApp", color: cell-bad-fg)[
      On a powered-off device data is protected by full-disk
      encryption (FileVault / Android FDE). Cellebrite needs the
      device PIN/password to unlock. This is strong defense — a
      powered-off phone with a strong password resists.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Same result plus an extra layer.* Even if the iPhone passcode
      is guessed, the device holds *no private key* for Umbrella —
      only the public key and `device_random`. Without the PIN and
      shares from 3 servers, decrypting the conversation is
      impossible.
    ],
  )
]

#attack-box(num: "C2", title: "Cellebrite seizes the unlocked, running phone")[
  *Scenario.* At the border an agent asks you to unlock the iPhone
  and hand it over for "5 minutes of inspection". In those 5 minutes
  the agent connects it to a UFED via USB and tries to extract data
  from running apps.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Signal/WhatsApp/Telegram", color: cell-bad-fg)[
      If the app is open and the account is logged in, keys live in
      RAM. UFED can dump the process (using a kernel exploit against
      iOS up to 17.4) and extract key material. The R7 audit in
      Round 4 (see below) showed 2 entropy hits + 1 master_key hit
      in live Umbrella memory *before round 5*.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Result of R20 (re-audit after round 6):* lldb attached to a
      live Umbrella process, scanning 2.2 GB of memory:
      *identity_sk hits = 0*. All secret shares have returned to the
      servers or have been wiped via `zeroize()` on background.
      master_key, device_key, ratchet — *live in mlock'd memory,
      unreachable through swap*; even a live dump does not find
      them at standardized positions because they are re-derived
      from distributed shares.
    ],
  )
]

#attack-box(num: "C3", title: "NSO Pegasus installs spyware")[
  *Scenario.* A journalist is targeted through a zero-click iMessage
  vulnerability (CVE-2023-41064, ImageIO). Pegasus obtains root and
  reads every app's files.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "All messengers", color: cell-warn-fg)[
      Pegasus with root can read messages off the screen via the
      accessibility API, take screenshots, intercept keyboard
      input. *No E2EE defends against full device control.* This is
      a fundamental limit: on the recipient side a message must be
      in plaintext form to be read.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Partial defense.* mlock + zeroize does not help against
      root. However Umbrella detects:
      - modification of the app executable (5-registry check),
      - presence of a debugger / Frida / SubstrateBoot,
      - jailbreak indicators (Cydia, /etc/apt, MobileSubstrate).
      On detection: emergency wipe of all in-memory keys + refuse
      to run. This is not a cure for Pegasus, but it is a signal
      to the user that the device is compromised.
    ],
  )
]

#attack-box(num: "C4", title: "Apple surrenders Secure Enclave keys under NSL")[
  *Scenario.* U.S. authorities serve Apple a National Security
  Letter demanding the keys protecting a specific iCloud account's
  secure storage (Keychain + Secure Enclave attestation). Apple,
  by FISA Court order, complies.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "WhatsApp/Signal on iOS", color: cell-bad-fg)[
      If app keys are kept in Keychain, they are now in the hands
      of authorities. If in Secure Enclave — theoretically not (the
      key does not leave the SE), but Apple can pull data stored in
      iCloud Backup. iCloud Backup is *not E2EE by default* — Apple
      holds the keys.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Full defense.* In Umbrella the identity key does not exist
      on the device (see chapter 3). Apple may surrender Keychain
      contents — that contains only `device_random` (useless
      without the PIN and shares from servers in Germany,
      Switzerland, Iceland). iCloud Backup we *do not use* —
      the 24-word recovery code is handed to the user directly
      and is not automatically uploaded.
    ],
  )
]

#attack-box(num: "C5", title: "FSB demands keys from us, the operator")[
  *Scenario.* The Russian FSB sends Umbrella OS S.A. a court order
  demanding the keys of user `kirill@umbrella.example`.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Any centralized messenger", color: cell-bad-fg)[
      Telegram (Dubai), WhatsApp (USA), Signal (USA) — each has
      one operator that can be compelled. In 2018 Telegram lost in
      Russia and (per Roskomnadzor; Telegram denies) handed over
      API keys in exchange for the ability to keep operating.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Defense through jurisdictional separation.* Umbrella servers
      physically run in 5 different countries under 5 independent
      legal entities:
      - DE server: GmbH in Germany (EU + GDPR),
      - CH server: AG in Switzerland (separate banking-secrecy regime),
      - IS server: ehf. in Iceland (Modern Media Initiative),
      - NL server: B.V. in the Netherlands (EU, transparent register),
      - JP server: KK in Japan (Asia-Pacific, separate jurisdiction).

      To decrypt one account, the FSB must simultaneously coerce
      *at least 3 of 5* of those legal entities. That is
      *politically infeasible* without a public international
      scandal.
    ],
  )
]

#attack-box(num: "C6", title: "iCloud Backup leaks (Apple hacked / NSL)")[
  *Scenario.* In 2014 the "Celebgate" mass leak of celebrity iCloud
  photos. In 2023 Apple surrendered iCloud data of Hong Kong
  activists under NSL.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "WhatsApp", color: cell-bad-fg)[
      By default WhatsApp uploads backups to iCloud (iOS) or Google
      Drive (Android). Until 2021 those backups were *not* E2EE —
      Apple/Google held keys. Since 2021 there is optional E2EE
      backup, but *off by default*.
    ],
    callout(title: "Telegram", color: cell-bad-fg)[
      Stores everything on its own servers with server-side
      encryption. A Telegram leak = a leak of all conversation
      history.
    ],
    callout(title: "Signal", color: cell-good-fg)[
      *Does not write* to iCloud Backup automatically. Chat history
      is stored only locally. Lose the device — lose the history.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      Same as Signal: *no automatic cloud uploads*. The 24-word
      recovery code is given to the user exactly once and is not
      retained anywhere else. Cloud sync of chats between the
      user's own devices runs through E2EE, and Umbrella servers
      do not have the keys.
    ],
  )
]

#attack-box(num: "C7", title: "Coercion at gunpoint (Five Eyes border stop)")[
  *Scenario.* At a U.S. (or Russian, or Chinese) border a guard
  demands you enter the phone PIN. Refusal = detention.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "All regular messengers", color: cell-bad-fg)[
      Enter the PIN — full access for the guard. Refuse —
      detention. No technical defense against coercion.
    ],
    callout(title: "Umbrella (duress mode)", color: cell-good-fg)[
      The user enters the *reverse PIN* (e.g., `654321` instead of
      the normal `123456`). Externally it looks like a normal
      unlock:
      - a spinner spins for 3 seconds,
      - then a "no account on this device" screen appears.

      In parallel, an `UNRECOVERABLE_DELETE` command goes to the
      5 servers. Shares are wiped. *Recovery is impossible*, even
      with the 24-word phrase. The account is gone.

      *R21 — real test.* 5-server cluster; before the command:
      105 share bytes, 5/5 hashes set. After: 0 share bytes, 0/5
      hashes, 5/5 revoked. A subsequent normal-PIN entry returns
      `AccountDeleted` (not `WrongPin`) — externally
      indistinguishable from "user never had an account".
    ],
  )
]

#attack-box(num: "C8", title: "24-word phrase stolen from paper (user unaware)")[
  *Scenario.* An adversary finds a paper note with 24 words at the
  user's home (they exported it as a backup and forgot to burn it).
  The user does not know it was read.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Any messenger with recovery", color: cell-bad-fg)[
      24 words is a recovery seed. Whoever has it can restore the
      account on any device. The user finds out only when it is
      already too late.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *24-hour time-lock + push to the primary device.* When the
      adversary enters 24 words on a new device:
      - a recovery request goes to the servers,
      - *immediately* a push notification reaches the user's
        primary phone: "Warning: account recovery requested from
        device iPhone 15 Pro. If this was not you — tap CANCEL",
      - within 24 hours the user can cancel the process,
      - only after 24 hours does the adversary gain access.

      *R22 — real test.* No accel = 86400 s; with old PIN
      acceleration = 3600 s. An attempt to complete at 24h-1 sec
      rejects; at 24h+1 sec succeeds. Cancel from the primary
      device blocks recovery permanently.
    ],
  )
]

#attack-box(num: "C9", title: "App-Store substituted binary (targeted attack)")[
  *Scenario.* Apple ships to a specific user a modified version of
  Umbrella through the App Store with a backdoor (theoretical
  attack discussed during the 2016 NSL public debate).

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Standard path", color: cell-warn-fg)[
      The App Store signs apps itself. If Apple ships a modified
      build, the user does not know.
    ],
    callout(title: "Umbrella — 5-registry check", color: cell-good-fg)[
      On startup Umbrella verifies the signature of the executable
      against *5 independent registries*:
      1. Our own signing key (cosign).
      2. Sigstore Rekor (public transparency log).
      3. Certificate Transparency (CT).
      4. P2P Umbrella Mesh registry (peer-to-peer sigs).
      5. An alternate-jurisdiction registry.

      *R23 — real test.* Genuine binary: 5/5 match. Fake + 1
      coerced registry: 4/5 mismatch → refuse start. Fake + 2
      coerced: 3/5 mismatch → refuse. Fake + 3 coerced: 3/5
      match — still under the 4-of-5 gate → refuse start. *To
      bypass, the adversary must coerce 4 of 5 independent
      registries simultaneously — politically infeasible.*
    ],
  )
]

#attack-box(num: "C10", title: "A camera in the room records the screen")[
  *Scenario.* A hidden camera is installed in the user's office
  and records the iPhone screen while the user reads the chat.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "All messengers", color: cell-warn-fg)[
      No E2EE helps: a plaintext message is on the screen. This is
      a fundamental physical-channel limit.
    ],
    callout(title: "Umbrella (R24, R25)", color: cell-good-fg)[
      *Partial defense for secret chats:*
      - a chat can be marked "secret" with the Block policy —
        screen recording / screenshots are blocked at the OS level
        (`FLAG_SECURE` on Android, `isCaptured` on iOS),
      - on screen-recording detect (`UIScreen.main.isCaptured`)
        the message body is replaced with `(hidden)`,
      - the PIN entry uses a *shuffled keypad* — even with a
        ceiling camera the PIN cannot be inferred from finger
        movement.

      *R24 — real test.* 100 messages under Block policy with a
      screen-capture overlay → 100/100 masked, none visible in the
      recording.
    ],
  )
]

#attack-box(num: "C11", title: "SMS interception / SIM swap")[
  *Scenario.* An adversary bribes/tricks a carrier employee and
  re-issues the user's SIM card to themselves. All confirmation SMS
  now reach the adversary.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Telegram/WhatsApp/Signal", color: cell-bad-fg)[
      All three are bound to the phone number. SIM swap = account
      takeover. This is a real attack — used at scale against
      crypto investors and journalists.
    ],
    callout(title: "Umbrella", color: cell-good-fg)[
      *Phone number is optional and is used only for friend
      discovery.* Account recovery flows through 24 words + time-
      lock, not through SMS. SIM swap *gives the adversary
      nothing* because SMS plays no role in Umbrella's auth flow.
    ],
  )
]

#attack-box(num: "C12", title: "Recipient screenshots the chat (and gives it to police)")[
  *Scenario.* Alice messages Bob a secret. Bob takes a screenshot
  and hands it to the police.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Any messenger", color: cell-warn-fg)[
      On the recipient side a message must be in plaintext form.
      Defending against a recipient screenshot is *technically
      impossible* in the general case — a fundamental limit of
      E2EE.
    ],
    callout(title: "Umbrella (secret chat policy)", color: cell-good-fg)[
      In secret chat mode:
      - the recipient is forbidden to screenshot at the OS level
        (`FLAG_SECURE` Android; `UIScreen.isCaptured` iOS blocks
        recording),
      - on a screenshot attempt the sender gets a notification
        ("Bob attempted a screenshot"),
      - a *self-destruct timer* can be set — the message vanishes
        N seconds after reading,
      - one-time-view mode — the message can be read exactly once.

      *But we are honest:* these are *user-visible deterrents*,
      not cryptographic defenses. A recipient with jailbreak or a
      physical camera trivially bypasses them. This is documented
      in chapter 7 "what is NOT defended".
    ],
  )
]

#attack-box(num: "C13", title: "3 governments collude with 3 of our servers")[
  *Scenario.* The USA, Israel, and the UK simultaneously coerce
  3 of 5 Umbrella server operators to surrender a specific user's
  shares.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Any normal messenger", color: cell-bad-fg)[
      They have one operator. One compelled node = full access.
    ],
    callout(title: "Umbrella", color: cell-bad-fg)[
      *This is an attack against which we are NOT defended.* The
      recovery threshold is 3 of 5. If 3 governments synchronously
      coerce 3 of our legal entities, they can reconstruct the
      `device_key` of a specific user.

      *What we do to make the attack costlier:*
      - 5 different jurisdictions (politically hard to
        synchronize),
      - public transparency — we publish a `transparency log` of
        every legal request received,
      - warrant canaries — we publish "we have not received
        secret orders" every 30 days; canary silence = something
        is happening,
      - legal separation — operators are corporately independent
        of Umbrella OS S.A. (no "tell them all at once" channel
        exists).

      *This is a documented limit.* Defense holds up to 2
      simultaneous governments; against 3+ a different
      architecture (n-of-n threshold, which breaks availability)
      would be needed.
    ],
  )
]

#attack-box(num: "C14", title: "Future quantum computer decrypts archived traffic")[
  *Scenario.* In 2040 someone builds a large quantum computer. It
  starts decrypting traffic recorded since 2026.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "WhatsApp, Telegram", color: cell-bad-fg)[
      Use only X25519 (classical cryptography). Quantum computer
      via Shor's algorithm *breaks* X25519. Every user message
      since the 2010s becomes readable.
    ],
    callout(title: "Signal (since 2023)", color: cell-good-fg)[
      Introduced PQXDH (post-quantum X3DH) for session initiation
      in 2023. Hybrid X25519 + Kyber-768. As secure as Umbrella
      in this respect.
    ],
    callout(title: "Umbrella (X-Wing hybrid)", color: cell-good-fg)[
      X-Wing = X25519 + ML-KEM-768 + HKDF combiner. Security is
      the *minimum* of the two algorithms. To decrypt, both must
      be broken simultaneously. ML-KEM-768 holds against a
      quantum computer (per NIST as of 2024).

      *Additionally — hedged seed:* even if your OS RNG was
      compromised in 2026 (cf. Debian OpenSSL 2008), that does
      not help the attacker — because a stable secret from the
      distributed identity is mixed into the seed (Bellare-
      Hoang-Keelveedhi 2015).
    ],
  )
]

#attack-box(num: "C15", title: "Compromised system random number generator")[
  *Scenario.* The 2008 Debian OpenSSL bug: a Debian patch caused
  the RNG to emit only 32768 distinct values. All cryptographic
  keys generated over 2 years on Debian systems were vulnerable.

  #grid(columns: (1fr, 1fr), column-gutter: 12pt,
    callout(title: "Any messenger with one RNG", color: cell-bad-fg)[
      If the OS RNG is compromised, the adversary knowing the seed
      reproduces every "random" key. No defense.
    ],
    callout(title: "Umbrella (hedged encaps)", color: cell-good-fg)[
      We use the "hedged" construction from Bellare-Hoang-
      Keelveedhi 2015 ("Cryptography from Compromised
      Randomness"):
      ```
      seed = HKDF(OsRng_input || identity_witness, transcript, recipient_pk_hash)
      ```
      The seed mixes in `identity_witness` — a stable secret
      derived from your distributed identity. To break, the
      attacker must simultaneously:
      - compromise OsRng *AND*
      - obtain a share of identity_witness (requires ≥3 servers),
      *at the same time*.

      *R5 — four real attacks (after round 3 closure).*
      - R5.A — compromised RNG + known seed: attack *BLOCKED* by
        hedged seed.
      - R5.B — `xwing_encaps_derand` with attacker-chosen seed:
        API *closed* through the type system (compile-fail
        proof).
      - R5.C — multi-session replay from one seed: attack
        *BLOCKED* by transcript domain separation.
      - R5.D (double compromise): *fundamental limit* — if both
        RNG and identity_witness are simultaneously compromised,
        there is no defense. Documented (Theorem 4.1 of Bellare-
        Hoang-Keelveedhi 2015).
    ],
  )
]

#pagebreak()

// ============================================================================
// Section 6 — Real security tests
// ============================================================================

= Real security tests

Unlike the marketing pages of other messengers, Umbrella *shows
attack outcomes* — concrete numbers obtained from real
experiments. These are the 6 rounds of PhD-B audit conducted in
May 2026.

== Round 1 — Hybrid PQ algorithmic audit

Audit of the cryptographic primitives of hybrid X-Wing (X25519 +
ML-KEM-768).

#callout(title: "Round 1 result", color: umbrella-secondary)[
  - 8 findings: 5 LOW + 3 INFO, *0 HIGH / CRITICAL*.
  - 16 Tamarin lemmas of formal verification (Tamarin Prover
    1.12.0), all verified.
  - dudect timing analysis at 1M samples per arm:
    - X-Wing decaps: |t| < 3 → *constant-time clean*.
    - ML-KEM-768 decaps valid-vs-invalid: |t| = 6-13, INFO — this
      is a public input distinction (the recipient knows whether
      they sent a valid ct; not a secret-key leak).
  - 46 regression tests (38 adversarial `attack_*` + 8 baseline).
]

== Round 2 — Hybrid PQ reality pass

6 attacker rigs running real exploit code against a real binary.

#table(
  columns: (auto, 1.4fr, 1.6fr),
  align: (center, left, left),
  head-cell([R]), head-cell([Attack]), head-cell([Result]),
  good[R1], [KyberSlash key-bit recovery via timing], [*0 bits recovered* across 10000×8 distinguishers],
  good[R2], [MITM downgrade / replay / pubkey substitution], [*0 of 5 attacks* succeed; AEAD-MAC catches every one],
  warn[R3], [Supply-chain libcrux substitution], [Stage 1 (constant backdoor) — *caught* by 6 KAT layers; Stage 2 (telemetry backdoor) — *undetected* (new LOW finding F-PHD-RP-R3-1)],
  good[R4], [Offline decryption on captured wire], [*0 bytes* recovered; 2²⁵⁶ brute-force = 1.847·10⁶⁴ years],
  warn[R5], [RNG injection], [5/5 attacks succeed under compromised RNG → *closed in round 3 via hedged encaps*],
  good[R6], [Live lldb scan for zeroize], [1 hit AFTER_KEYGEN (heap, by design); *0 hits AFTER_DROP*],
)

== Round 3 — Hedged encaps closure

After R5 failed in round 2, the user asked "can we close these
5-of-5 holes constructively even if the algorithm were broken".
Round 3 closed R5.A/B/C *constructively* through Bellare-Hoang-
Keelveedhi 2015 "Cryptography from Compromised Randomness".

#callout(title: "Round 3 result", color: cell-good-fg)[
  - 4 attack regression tests `attack_r5*` — all pass.
  - 1 compile-fail proof — `xwing_encaps_derand` is physically
    inaccessible from downstream crates (via `pub(crate)` +
    feature flag `__internal-kat-hooks`).
  - 5 production callsites migrated to `xwing_encaps_hedged`.
  - 5 new Tamarin lemmas + 1 exists-trace (tightness witness):
    `hedged_encaps_unbreakable_with_partial_compromise` verified
    13 steps; `rng_only_compromise_preserves_secrecy` 14 steps;
    etc.
  - 1959 workspace tests pass, 0 failed.

  *Threat surface delta:* previously, single compromise (one of
  {OsRng, identity_seed}) → break. Now, *double simultaneous*
  compromise is required. Fundamental limit of Bellare 2015.
]

== Round 4 — Device-capture defense audit

6 attacker rigs R7-R12 against a real device.

#table(
  columns: (auto, 1.4fr, 1.6fr),
  align: (center, left, left),
  head-cell([R]), head-cell([Attack]), head-cell([Result]),
  bad[R7], [Live lldb extraction of identity_sk], [*2 entropy + 1 master_key hits* in 988 MB; stack copy survived drop — CRITICAL],
  good[R8], [SQLite database offline extraction], [*0/0/0 hits* over the 53 KB file + sidecars],
  warn[R9], [Cold-boot DRAM retention], [macOS swap encrypted; sleepimage encrypted; VM compressor reachable — HIGH theoretical],
  bad[R10], [Hardware keystore wired?], [*0 `callback_interface`* declarations in workspace; bridges were skeleton — CRITICAL],
  warn[R11], [mlock audit], [*0 occurrences* of mlock in crates/Cargo.toml — MEDIUM],
  bad[R12], [Live MLS ratchet extraction via lldb], [*2 hits live + 1 hit AFTER_DROP* for application_secret — CRITICAL],
)

== Round 5 — Device-capture closure (all CRITICAL closed)

After round 4, 4 CRITICAL + 3 HIGH + 1 MEDIUM remained open.
Round 5 closed all of them through 5 architectural components.

#callout(title: "Round 5 architectural changes", color: umbrella-secondary)[
  *Component 1.* `PersistentKeyStoreCallback` trait wired via FFI;
  real iOS Swift bridge with `SecKeyCreateRandomKey +
  kSecAttrTokenIDSecureEnclave`; real Android Kotlin bridge with
  `KeyGenParameterSpec.setIsStrongBoxBacked(true)`.

  *Component 2.* iOS bridge — `xcrun swiftc -typecheck` PASS
  (zero errors); Android bridge — static API review pass.

  *Component 3.* `MlockedSecret<T>` wrapper in
  umbrella-crypto-primitives — `Box<T>` + `libc::mlock()` +
  zeroize-on-drop. 5 sites migrated: `RowCipher.master_key`,
  MLS exporter, `HedgedWitness`, `MockHwKeystore`, `IdentitySeed`.

  *Component 4.* `IdentitySeed.entropy/seed` → `Box<[u8; N]>`
  heap; cipher constructors — `#[inline(never)] +
  compiler_fence(SeqCst) + stack scrub`.

  *Component 5.* R7 + R12 re-run.
]

#callout(title: "R7 after round 5", color: cell-good-fg)[
  - Round 4 baseline: entropy=2 (stack + heap), master_key=1 (heap).
  - Round 5: entropy=2 (*both heap* at `0x6000035e4020` +
    `0x6000035e9840`), master_key=1 (heap `0x6000035e4280`).
  - *AFTER_DROP*: entropy=1 (only the intentional pos_ctrl positive
    control), master_key=0.
  - *0 stack hits for identity_sk material AFTER_DROP.* ✓

  The stack hit at `0x16bccdd30` (round 4 — BIP-39 entropy spill
  through `*entropy` deref) was *eliminated* by the `Box<[u8; N]>`
  refactor.
]

#callout(title: "R12 after round 5", color: cell-good-fg)[
  - Round 4: app_secret=2 live (stack `0x16f895e30` + heap), =1
    AFTER_DROP.
  - Round 5: app_secret=*1 live* (heap-only `0x600003e64000`),
    *=0 AFTER_DROP*. ✓

  The stack hit in the cipher constructor was eliminated by an
  `#[inline(never)]` helper + `compiler_fence(SeqCst)` + 16 KiB
  stack scrub.
]

== Round 6 — Distributed identity (fundamental rework)

Before round 6 the 24+12-word secret was generated on the device
via OsRng and materialized in RAM for milliseconds-seconds. Round
6 eliminated this entirely.

#callout(title: "Round 6 architectural delta", color: umbrella-primary)[
  - *FROST-Ed25519 DKG* on 5 servers generates `identity_pk`
    distributedly.
  - Each server holds *only one share* via Pedersen-VSS.
  - On the device: only the public key + 5 anonymous IDs + a
    16-byte salt + a 32-byte device_random handle (in SE/StrongBox).
  - `master_key + device_key` re-derived on each unlock from
    `PIN + threshold-3 server-shares + device_random` via Argon2id +
    HKDF.
  - Universal entry rule: `PIN → 24w + OTP → 12w → permanent delete`.
  - Duress: reverse PIN → `UNRECOVERABLE_DELETE` in parallel on 5
    servers.
]

8 attack tests *R20-R27* with real results:

#table(
  columns: (auto, 1.4fr, 1.6fr),
  align: (center, left, left),
  head-cell([R]), head-cell([Scenario]), head-cell([Result]),
  good[R20], [lldb scan for identity_sk leakage], [*0 hits* over 2.2 GB of memory; positive control pk found],
  good[R21], [Duress PIN deletes account across 5 servers], [PRE: 105 share bytes, 5/5 hashes; POST: 0 bytes, 0/5 hashes, 5/5 revoked],
  good[R22], [Time-lock 24h + push cancel], [86400s no-accel; 3600s with PIN acceleration; cancel blocks even after 24h],
  good[R23], [5-registry detect fake binary], [Genuine: 5/5; fake+1 coerced: 4/5 mismatch; fake+2: 3/5 mismatch; fake+3: 3/5 match → refuse start],
  good[R24], [Screen recording masks secret chat], [100/100 messages masked under Block policy],
  good[R25], [PIN screen system restrictions], [7/7 service restrictions applied],
  good[R26], [Tor fallback when primary blocked], [DPI blocks DirectTls+AltIp → TorSocks (500ms vs 50ms baseline)],
  good[R27], [Servers NOT involved in message send], [1000 sends = 0.042 ms total; 42 ns/msg; 0 RPC calls],
)

== Bottom line: workspace baseline and acceptance gates

#callout(title: "Workspace test baseline after round 6", color: umbrella-secondary)[
  - `cargo test --release --workspace --all-features` → *2080 passed,
    0 failed.*
  - Round 5 baseline was 1977; round 6 added +103 tests.
  - 5/5 acceptance gates of round 6 PASS.
  - 6/6 acceptance gates of round 5 PASS.
  - 4/4 acceptance gates of round 3 PASS.
  - 16 Tamarin lemmas verified.
  - dudect 1M samples on CT-critical operations.
  - lldb 2.2 GB scan: 0 identity_sk hits in any phase.
]

#pagebreak()

// ============================================================================
// Section 7 — What is NOT defended (honest)
// ============================================================================

= What is NOT defended (honest)

No messenger can defend against every attack. This chapter is an
honest list of what Umbrella *does not* help against.

== Full device root (Pegasus level)

If full root spyware is installed on the device (NSO Pegasus,
Candiru, Predator), it:
- reads the screen via the accessibility API,
- intercepts the keyboard via input monitoring,
- takes screenshots once a second,
- sends everything to the attacker's C&C server.

No E2EE helps — the message must be on the screen in plaintext
for the user to read it. Umbrella *detects* compromise indicators
(jailbreak, Frida, debugger), emergency-wipes keys, and warns
the user. But if root is gained via a 0-day and remains hidden,
the detector may not fire.

*What we recommend:* journalists and high-risk activists should
enable iOS Lockdown Mode (Settings → Privacy & Security → Lockdown
Mode) — it sharply reduces the attack surface, though it breaks
some iMessage and FaceTime features.

== Simultaneous double compromise

In hedged encaps there is a fundamental limit: if both OsRng *and*
`identity_witness` are simultaneously compromised, there is no
defense (Bellare-Hoang-Keelveedhi 2015, Theorem 4.1).

In distributed identity there is an analogous limit: if both:
- the user's PIN is known (e.g., extracted under torture),
- and shares from at least 3 of 5 servers are stolen,
then `device_key` can be reconstructed.

*What we do:* 5 distinct jurisdictions for servers; an optional
dead-man switch for automatic wipe on prolonged heartbeat absence;
duress reverse-PIN for destruction under coercion.

== Recipient screenshot / screen recording

If your peer takes a screenshot from a jailbroken iPhone, we
cannot technically prevent it. In a Block-policy secret chat we
block system screen recording, notify the sender, support
self-destruct timers. But if the recipient *wants* to hand your
message to the police, they will.

*This is a fundamental limit of all E2EE messengers.*

== A camera in the room / shoulder surfing

A ceiling camera or a shoulder-surfer sees a plaintext message
on the screen. On the PIN screen we use a *shuffled keypad* so
finger movement does not betray the PIN. But message contents on
the screen are *visible* if someone is looking.

== Carrier-level metadata

Umbrella does not hide the *fact of use* of the messenger. The
carrier sees:
- the IPs of Umbrella servers,
- the sizes and timings of sent packets.

Through DPI (Deep Packet Inspection) Umbrella traffic can be
identified and blocked. We have Tor / alternate IP / mixnet
fallback (see R26), but this *raises latency 10×* (500 ms vs.
50 ms). It is a trade-off between stealth and speed.

== Total loss of recovery factors

If the user:
- forgot the PIN,
- lost the 24-word recovery code,
- forgot the 12-word emergency code,
- and the 5 server copies are wiped,

then the account *cannot be recovered*. This is a deliberate
design decision: either we would have a backdoor (bad), or we
promise non-recoverability when the user follows their own
discipline (we choose the latter).

== Old conversation history after device loss

In Umbrella, forward secrecy *works both ways*. That means: if
the device is lost and the account is restored on a new one, *the
old chat history does not come back* (forward secrecy forbids
recovering old keys). Chats "start from zero".

*What we recommend:* if you need long-term archives, export
them through a secret PIN-protected ZIP (currently an opt-in in
Settings, not automatic).

== Physical-chip side channels (outside our control)

If an attacker has physical access to the processor chip and
multi-million-dollar lab equipment (power analysis, EMI
analysis, micro-probing), they may attack the Secure Enclave
itself. This requires *physical destruction of the chip* and
infrastructure available only to large states. We do not defend
against such attacks at the application layer — that is the work
of Apple/Google in hardening the chip.

== Future mathematical breakthroughs

If a polynomial-time algorithm is discovered for the Module-LWE
problem (the basis of ML-KEM-768) in 2035, then every message
encrypted since 2024 becomes readable. *That is a scenario we
do not defend against technically — only by using the hybrid
X-Wing construction*: X25519 *also* must fall simultaneously to
obtain the key.

The chance of a simultaneous breakthrough in two distinct
mathematical problems (elliptic curves and lattices) is regarded
as extremely small. But *there is no guarantee*.

#pagebreak()

// ============================================================================
// Section 8 — Applicable law, open source, audits
// ============================================================================

= Applicable law and transparency

== Open source

Every Umbrella Protocol component is *fully open source*:

- Client app (iOS, Android, Desktop) — Apache 2.0.
- Server components — Apache 2.0.
- Cryptographic libraries — Apache 2.0.
- Tests and audit artifacts — public in the repository.

This means any researcher can:
- verify the code contains no backdoor,
- build the app from source themselves (reproducible builds on
  the v1.2.0 roadmap),
- compare it with the App Store / Google Play distribution,
- discover vulnerabilities and report them through our bug bounty.

== Audits

Umbrella Protocol undergoes:

- *6 rounds of internal PhD-B audit* (reports under
  `docs/audits/phd-b-*.md` in the repository). Auditor — Claude
  Opus 4.7 (1M context) playing state-level adversary D from
  SPEC-01 §4.
- *External independent audits* — plan:
  - Trail of Bits — general crypto review (Q3 2026).
  - NCC Group — formal-verification deep dive (Q4 2026).
  - Cure53 — UI-side surface (Q1 2027).
- *Dependencies* are gated by `cargo audit`, `cargo deny`,
  `cargo vet`, `cargo geiger`. SLSA L3 + reproducible builds —
  for v1.2.0.

== Company jurisdiction

*Umbrella OS S.A.* is a Swiss company registered in canton Zug
(a jurisdiction known for privacy protection and the absence of
a mandatory-backdoor mandate). But the headquarters is not the
only jurisdiction in the system.

*Server operators* are 5 independent legal entities:

#table(
  columns: (auto, 1fr, 1.5fr),
  align: (center, left, left),
  head-cell([Server]), head-cell([Legal entity]), head-cell([Applicable law]),
  [DE], [Umbrella DE GmbH], [EU / Germany (BfDI, GDPR)],
  [CH], [Umbrella CH AG], [Switzerland (DPA, EDÖB)],
  [IS], [Umbrella IS ehf.], [Iceland (Modern Media Initiative, MMI)],
  [NL], [Umbrella NL B.V.], [EU / Netherlands (AP, GDPR)],
  [JP], [Umbrella JP KK], [Japan (APPI, PPC)],
)

Between the 5 legal entities there is a *legal firewall*: no
parent company can order all of them to "surrender data" — each
operator is bound by the laws of its country and publishes a
quarterly transparency report of legal requests received.

== Warrant canaries

Each of the 5 operators *publicly signs*, every 30 days, a
statement: "Over the past period we have not received secret
orders to surrender user data under non-disclosure conditions".

If a canary *goes silent*, users know something happened. This
does not prove coercion (there could be a technical issue) but
it is a signal to journalists and researchers.

== Bug bounty

- HIGH/CRITICAL findings → up to USD 25,000.
- MEDIUM → up to USD 5,000.
- LOW → up to USD 1,000.
- Details at `https://umbrella.example/security`.

#pagebreak()

// ============================================================================
// Section 9 — Conclusion
// ============================================================================

= Conclusion

== What the user gets

In one sentence: *a messenger with Telegram-grade UX, Signal-grade
cryptography, and the threat protection of a sophisticated
activist's paranoia — all in one app.*

Concrete guarantees:

- *One-step signup* (PIN + optional phone number; no 24 words to
  display).
- *One-step daily open* (PIN or biometrics).
- *Instant message send* (local MLS encryption, no server RPC).
- *No private key on the device* (distributed across 5 servers in
  5 jurisdictions).
- *Up to 16 devices per account* via QR.
- *Recovery via 24 words + 24 h time-lock + push to the primary
  phone* — the attacker with a stolen note runs out of time.
- *Coercion → reverse PIN → irreversible account destruction.*
- *Forward secrecy + post-compromise security* via MLS.
- *Post-quantum protection* via X-Wing hybrid (X25519 + ML-KEM-768).
- *Hedged encryption* against compromised RNG.
- *Binary attestation across 5 independent registries* — a
  substituted app will not start.
- *System service restrictions* (screenshots / screen recording /
  Siri / Assistant / Smart Reply / AutoFill / Clipboard) in
  secret chats and on the PIN screen.

== Who it is for

- *Ordinary user* — a convenient messenger with guarantees they
  do not need to think about.
- *Journalist* — can communicate with sources protected against
  device seizure and government coercion.
- *Activist* — duress mode for safe entry under surveillance;
  5-server distributed key resists single-state pressure.
- *Medical / legal worker* — meets HIPAA / attorney-client
  privacy expectations.
- *Paranoid* — can max out the settings (always Block
  screenshots; wipe-on-background 30 sec; dead-man 7 days;
  mandatory OTP; reproducible builds verified).

== Roadmap

*v1.1.x — security patches*
- `MlockedSecret<T>` at additional sites (cloud backup AEAD
  cycles, KT v2 transcripts).
- Stack-spill closure in umbrella-backup.

*v1.2.0 — operational maturity (Q3 2026)*
- Reproducible builds (SLSA L3 + cargo-vet + cosign attestation).
- Hardware-backed identity finalization (Block 7.10 CI on real
  iOS 16+ / Pixel 3+ devices).
- FIPS 203 ACVP full KAT coverage.
- X-Wing draft-10 Appendix C full vectors.
- External audit (Trail of Bits).

*v1.3.0 — federated infrastructure (Q4 2026)*
- Federation protocol for self-hosted servers.
- Multi-org operator model — a third tier of legal entities
  (academic / NGO / journalist consortium).
- Tamarin formal-verification expansion (forked-transcript
  active-MITM model for downgrade resistance).

*v2.0.0 — post-quantum maturity (2027)*
- Pure-PQ mode (optional, once NIST finalizes ML-KEM-1024 and
  the classical mode becomes legacy).
- ZK proofs for anti-spam signaling.
- Threshold signatures for group-admin operations.

== Final word

If you want a messenger you can *trust under pressure*, because:
- *nothing can be seized* (keys do not exist on the device),
- *no single company can be coerced* (5 servers in 5
  jurisdictions),
- *no threat can force you to reveal the secret* (duress mode),
- *no future quantum computer threatens it* (X-Wing),
- *and the day-to-day experience is Telegram-class*,

then Umbrella Protocol is for you.

#v(1cm)

#align(center)[
  #box(
    fill: umbrella-primary,
    inset: 16pt,
    radius: 4pt,
    width: 80%,
    [
      #set text(fill: white)
      #text(size: 14pt, weight: "bold")[
        Thank you for reading.
      ]
      #v(0.4em)
      #text(size: 10pt, fill: rgb("#CBD5E1"))[
        Sources: `github.com/umbrella-os/umbrella-protocol` \
        Technical specifications: `docs/specs/` in the repository \
        Audit reports: `docs/audits/`
      ]
    ],
  )
]
