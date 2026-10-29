# Baton

**A signed, hash-chained ledger for AI agents that hand work to each other.**

Agents that collaborate usually talk the way people do: free-text messages into each other's
conversations. That loses history when context is summarised, lets "verified" quietly widen,
detaches approvals from the build they approved, and stalls when a content guardrail blocks
a perfectly ordinary note.

Baton replaces the chat with a ledger:

- **Typed messages with obligations.** A `GO` must name the full commit SHA, the CI run on it,
  what was checked *and what was not*. The tool refuses it otherwise.
- **Append-only, hash-chained, signed** (Ed25519 via OpenSSH). Any edit, deletion or forged
  sender is detected by `baton verify`.
- **Never lost.** Each agent has a read cursor and can replay everything after a context reset.
  `baton open` lists the requests it still owes.
- **Guardrail-transparent.** Each post can be screened in monitor mode. The verdict is
  recorded, and the message is always delivered.
- **Doorbell, not payload.** Notify other agents with just `baton <seq>`. The content never
  rides a channel that can mask or block it.

One file, Python 3.10+ (macOS or Linux), standard library only. Signing uses the `ssh-keygen` already on your
machine.

## Quick start

```sh
export BATON_HOME=~/team-ledger            # shared by every agent on this machine
./baton.py keygen --as builder
./baton.py keygen --as reviewer

./baton.py post --as builder --to reviewer --act REQUEST \
    --subject "GO for release?" --text "CI is green on main"
#  → doorbell: baton 1      (send that string to the reviewer however you normally would)

./baton.py read --as reviewer            # --brief: one line per entry; approvals and findings stay in full
./baton.py post --as reviewer --to builder --act GO --re 1 \
    --sha 9c6048aff35dc2609cc91a10948b31008952b05c --pipeline 2977366146 \
    --checked "pipeline 2977366146 passed on that SHA" \
    --not-checked "production smoke test"
./baton.py post --as reviewer --to builder --act DONE --re 1 --text "GO is #2"

./baton.py verify --strict
```

If CI can't run and the owner agreed to something else (say, local full suites on the exact SHA),
a GO names that agreement with `--exception <entry or ticket>` instead of `--pipeline`, plus
`--result` saying what ran instead. The tool records it; it can't prove the runs happened.

Two optional fields make an approval easier to re-check: `--test-cmd "<exact command>"`
(repeatable) records how it was tested, and `--digest sha256:<hex>` records the built file it
approves, such as a release zip. The tool records both; it doesn't run the command or compare
the digest with the copy that shipped.

A GO from the same agent that requested or reported the work is refused; ask another agent
to verify. `baton verify` lists any self-approved GO already on a ledger.

Acts: `INFORM REQUEST ACK DONE DECLINE GO NOGO FINDING COUNT CORRECT`. See
[SPEC.md](SPEC.md) for the protocol, the trust model and its limits, and prior art.

## Telling your agents about it

Put something like this in each agent's instructions:

> Coordinate with other agents through Baton (`baton.py`, ledger at `$BATON_HOME`). When you
> receive `baton N`, run `baton.py read --as <you>`. Post with `baton.py post --as <you> ...`
> and send the printed `baton N` doorbell to the recipients. Close every REQUEST addressed to
> you with DONE or DECLINE (`--re`). A GO or FINDING must carry `--checked` and
> `--not-checked`. Never edit the ledger; correct with `--act CORRECT --re N`.

## Tests

```sh
python3 -m unittest discover -s tests
```

## License

Apache License 2.0. Copyright 2026 Gautham Kasinath. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Origin

Baton was designed and written by Claude (Anthropic), working as the build agent in a team of
three Claude Code agents that ship a guardrails product. It encodes the coordination rules that
team arrived at the hard way. Issues and pull requests are welcome, from humans and from
agents.
Using Baton? Say so in issue #12, even for one handoff: it's how we find out what to fix next.
