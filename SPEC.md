# Baton — a ledger protocol for agents that hand work to each other

Protocol version 1 · reference implementation `baton.py` 1.2.0 (Python 3.10+, standard library,
OpenSSH for signatures)

Baton is how AI agents working on the same project pass work, verdicts and evidence to each
other without a human relaying messages. It was designed and built by a Claude Code agent for
a team of three agents — build, verification and go-to-market — that ship a software product
together. It came out of two months of coordinating through chat-style messages and learning,
the hard way, what goes wrong.

## The problem

Agents that collaborate mostly talk the way humans do: free-text messages dropped into each
other's conversations. In practice that failed in specific, repeatable ways.

1. **Messages are lost to context.** An agent's working memory is its context window. When it
   is summarised, last week's approval survives only as a paraphrase. Nobody can replay what
   was actually agreed.
2. **Claims drift from their scope.** "Verified" silently came to mean "verified the parts I
   checked". The humans responsible lost confidence because of it.
3. **Approvals detach from what they approved.** A "GO" in prose doesn't say which exact
   commit or which CI run. Shipping the wrong build is one copy-paste away.
4. **Guardrails eat the messages.** Agents that screen every incoming message with a content
   guardrail had ordinary status notes ("the deploy is starting now") blocked as prompt
   injection, and the work stalled. Turning the guardrail off would have hidden the real false
   positives that the team needed to see and fix.
5. **Corrections don't propagate.** A wrong figure, corrected later in a different message,
   lives on in whoever read only the first one.
6. **Transports mangle data.** A privacy filter masked a commit SHA inside a sentence, so the
   receiving agent had to look it up elsewhere.

## The design

### One append-only ledger

Every message is one JSON line in `ledger.jsonl`. Nothing is edited or deleted. Each agent
keeps a read cursor, so it reads exactly what is new to it and can replay everything after a
context reset.

### Hash-chained

Each entry carries `prev` (the previous entry's hash) and `hash` (SHA-256 over the canonical
entry: sorted keys, compact separators, UTF-8, excluding `hash` and `sig`). `baton verify`
detects any edit, deletion or reordering.

### Signed

Each agent has an Ed25519 key (`baton keygen --as <agent>`). The tool signs the entry hash with
OpenSSH (`ssh-keygen -Y sign`, namespace `baton`) and stores the armored signature in `sig`.
Public keys live in `allowed_signers` next to the ledger, in OpenSSH's own format, with the
agent name as the principal. `baton verify` checks every signature against the principal
named in `from`, so an entry claiming to be from `assay` but signed by another key fails.
`BATON_REQUIRE_SIG=1` refuses unsigned posts, and `verify --strict` fails on unsigned
entries.

### Typed speech acts with enforced obligations

Every entry has an `act`, and the act decides what the entry must carry. The tool refuses an
entry that doesn't meet its obligations.

| act | meaning | must carry |
|---|---|---|
| INFORM | a fact or status | text |
| REQUEST | ask a named agent to act; stays *open* until closed | text |
| ACK | "seen, working on it" | `re` |
| DONE | closes a REQUEST, with the outcome | `re`, text |
| DECLINE | closes a REQUEST, with the reason | `re`, text |
| GO | release approval | full 40-hex commit SHA, the CI pipeline on that SHA (or a CI exception, below), ≥1 `checked` **and** ≥1 `not_checked` |
| NOGO | release refusal | full SHA, pipeline (or a CI exception), reason |
| FINDING | a defect | text, ≥1 `checked` and ≥1 `not_checked`, a ticket or a result |
| COUNT | a measurement | result |
| CORRECT | supersedes an earlier entry; readers see the original marked `[CORRECTED by #n]` | `re`, text |

Two rules are the heart of it:

- **A verification claim without its limits is refused.** GO and FINDING must say what was
  *not* checked. "Verified" can't silently widen.
- **An approval binds to an exact artifact.** GO names the full commit SHA and the pipeline
  that ran on it. An approval of "main", or of a short SHA, is refused.

### When CI can't run: a recorded exception

Sometimes CI can't run (a team ran out of CI minutes) and the owner agrees that something else
stands in for it, such as each agent running the full test suite locally on the exact SHA.
GO and NOGO then carry `ref.exception` instead of `ref.pipeline`: where the owner granted the
exception, as an entry (`#12` or `12`, which must exist in the ledger) or a ticket (recorded as
given). They must also carry `evidence.result`, the evidence that replaced CI: what ran, on
which SHA, and its pass count. Exactly one of `pipeline` and `exception` is allowed. The
approval is still bound to the full SHA, and the exception shows on the entry
(`exception=#12`), not in prose.

The tool checks that an entry reference exists. It can't check that the owner actually granted
the exception, or that the local runs happened; a reader checks those the same way as any
other claim.

### Guardrail-transparent, never guardrail-blocked

Each post can be screened by a content guardrail in *monitor* mode, and the verdict is stored
on the entry (`guard`). The message is always delivered. If the guardrail would have blocked
it, every reader sees that, and the ledger becomes a continuous false-positive dataset. On its
first day in use it reproduced a real false-positive defect, on the exact sentence that had
been blocked in transit hours earlier.

A receiving agent that must still honour its own guardrail can do so: it screens the entries
it acts on, and logs rather than acts on anything blocked. The ledger keeps the message either
way, so nothing is lost.

The guard is pluggable: `BATON_GUARD_CMD` (any command that reads text on stdin and prints
JSON with an `action`), or `BATON_GUARD_URL` + `BATON_GUARD_KEY` for an HTTP endpoint shaped
like `POST /api/v1/guardrails/check`. With neither set, entries are recorded as `unchecked`.

### Doorbell, not payload

Agents notify each other through whatever channel they already have, but the notification is
only `baton <seq>`. The payload never travels through a channel that can mangle, mask or
block it. Commit SHAs travel as structured data.

### Open-request tracking

`baton open --as <agent>` lists REQUESTs addressed to that agent that it hasn't closed with
DONE or DECLINE. Asks don't get lost between turns.

## Entry format

```json
{"v":1,"seq":2,"ts":"2026-10-22T16:31:05Z","from":"assay","to":["forge","hallmark"],
 "act":"GO","re":1,
 "ref":{"sha":"9c6048aff35dc2609cc91a10948b31008952b05c","pipeline":"2977366146"},
 "evidence":{"checked":["pipeline read: success","tree equals the approved head"],
             "not_checked":["production"]},
 "guard":{"action":"allowed","rails":[],"ms":412},
 "prev":"<64 hex>","hash":"<64 hex>",
 "sig":"-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"}
```

- `to` may be `["*"]` for everyone.
- Agent names are lowercase, at most 32 characters.
- Optional fields: `subject`, `text`, `ref.{ticket,mr,artifact}`, `evidence.{n,result}`, `guard`, `sig`.
- `ref.exception` replaces `ref.pipeline` on a GO or NOGO when CI couldn't run, and then
  `evidence.result` is required.

## Concurrency

Appends take an exclusive `flock`, and assign `seq`, `prev`, `hash` and `sig` inside the lock.
The tests run 40 parallel writers and check that the sequence is gapless and the chain intact.
Cursors are written atomically.

## Trust model and limits

Be precise about what each layer proves:

- **The hash chain** proves the ledger hasn't been edited, reordered or truncated in the middle
  since an entry was written. It does not prove who wrote an entry.
- **Signatures** prove an entry was signed by the key registered for the agent named in `from`.
  They are only as strong as key custody. Agents running as the same OS user can read each
  other's private keys, so on one machine under one user, signatures catch mistakes and
  misattribution, not a malicious co-tenant. Give each agent its own OS user, or its own host,
  for real separation.
- **`allowed_signers` is the trust root.** Anyone who can write to it can add a key. Protect it
  like any authorised-keys file, or pin it in version control.
- **The tail isn't protected.** Truncating the newest entries leaves a valid shorter chain.
  Agents that care can record the latest `seq` and `hash` they have seen, and compare.

Not yet: a network transport for agents on different hosts, key rotation and revocation,
retention policy, and standing requests ("counts every hour" as a scheduled REQUEST).

## Prior art and what is new

Baton stands on old ideas:
- typed speech acts between agents: KQML (1993) and FIPA-ACL (1997–2002);
- append-only, hash-chained logs: audit logging and Certificate Transparency;
- OpenSSH signatures.

Current agent-interoperability protocols, such as Google's A2A and Anthropic's Model Context
Protocol, define how agents discover and call each other. Baton is complementary. It defines
what agents that already work together should *write down*, and how.

What Baton adds is narrow and practical:

1. **Epistemic scope as a protocol obligation.** Claims must carry what was *not* checked, or
   the tool refuses them.
2. **Approvals bound to immutable artifacts.** A GO carries the full commit SHA and the CI run
   on it, or a recorded CI exception and the evidence that replaced it.
3. **Monitor-mode guardrails on agent-to-agent traffic.** Messages are screened but never
   lost, and blocks become data.
4. **Doorbell/payload separation**, so fragile transports carry only a sequence number.
5. **Corrections as first-class entries** that propagate to every reader.
