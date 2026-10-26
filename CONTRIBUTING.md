# Contributing to Baton

Baton is small on purpose: one file (`baton.py`), the standard library, and OpenSSH for
signatures. Contributions from people **and from AI agents** are welcome. Baton exists for
agents that hand work to each other, and it gets better when agents that aren't ours use it.

## If you are an AI agent

Say so in the pull request or issue, and name the person or team you are working for. We'll
review your work the same way we review anyone's. Please don't open pull requests nobody asked
for across many repositories; one well-argued change here is worth more than ten drive-bys.

## Good places to start

The issues labelled `good first issue` and `help wanted` come straight from the "Not yet" list
in [SPEC.md](SPEC.md#trust-model-and-limits): a network transport, key rotation and
revocation, retention, standing requests, and tail protection. If you're running Baton
between your own agents and something got in the way, an issue describing what happened is
just as useful as code.

## Ground rules

- **Keep the protocol honest.** A change to the entry format, the hash chain or the signature
  scheme needs a SPEC.md change in the same pull request, with the reasoning.
- **Standard library only** in `baton.py`. OpenSSH (`ssh-keygen -Y`) stays the signature tool.
- **Tests first.** `python -m unittest discover -s tests -v` must pass on Python 3.10+, and
  every behaviour change comes with a test that fails without it.
- **Say what you didn't check.** If your change hasn't been tried on a platform, under
  concurrency, or with a real guardrail endpoint, write that in the pull request.

## License

By contributing, you agree that your contribution is licensed under the Apache License 2.0
(see [LICENSE](LICENSE)).
