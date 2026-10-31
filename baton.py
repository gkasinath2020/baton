#!/usr/bin/env python3
# Copyright 2026 Gautham Kasinath
# SPDX-License-Identifier: Apache-2.0
"""Baton: an append-only, typed, hash-chained, signed message ledger for agents that work together.

See SPEC.md for the protocol. This file is the reference implementation: one file, Python 3.10+
standard library only, signatures via OpenSSH (`ssh-keygen -Y`, Ed25519).

    baton keygen --as forge
    baton post --as forge --to assay --act REQUEST --text "GO for this build?" \
               --sha <40-hex> --pipeline 123
    # no CI run? name the owner's exception instead, plus what replaced CI:
    #          --sha <40-hex> --exception 12 --result "local suite 217/217 on <sha>, twice"
    # and the built file it approves:  --digest sha256:<64 hex>
    # say how it was tested:  --test-cmd "python3 -m unittest discover -s tests"
    baton read --as assay          # unread entries addressed to assay; advances its cursor
    baton open --as assay          # REQUESTs to assay that assay hasn't closed
    baton verify [--strict]        # hash chain + every signature
    baton thread 57 | show 57 | tail -n 20
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone

__version__ = "1.5.1"

VERSION = 1
GENESIS = "0" * 64
NAMESPACE = "baton"

ACTS = {
    # act: (needs_re, needs_text)
    "INFORM": (False, True),
    "REQUEST": (False, True),
    "ACK": (True, False),
    "DONE": (True, True),
    "DECLINE": (True, True),
    "GO": (False, False),
    "NOGO": (False, True),
    "FINDING": (False, True),
    "COUNT": (False, False),
    "CORRECT": (True, True),
}
CLOSERS = {"DONE", "DECLINE"}
# Acts whose scope or correction must survive skimming: read --brief prints them in full.
FULL_IN_BRIEF = {"GO", "NOGO", "FINDING", "CORRECT"}
# Guard verdicts worth a reader's attention. Others ("allowed", "monitored", "unchecked")
# stay on the entry but are not flagged.
FLAGGED = {"blocked", "modified"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$")
SEQREF = re.compile(r"^#?(\d+)$")
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class BatonError(Exception):
    pass


# ---------------------------------------------------------------- paths
def home():
    return os.environ.get("BATON_HOME", os.path.expanduser("~/.baton/ledger"))


def ledger_path():
    return os.path.join(home(), "ledger.jsonl")


def signers_path():
    return os.path.join(home(), "allowed_signers")


def keys_dir():
    return os.environ.get("BATON_KEYS", os.path.expanduser("~/.baton/keys"))


def key_path(who):
    return os.path.join(keys_dir(), who)


# ---------------------------------------------------------------- hashing
def _canon(entry):
    body = {k: v for k, v in entry.items() if k not in ("hash", "sig")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry):
    return hashlib.sha256(_canon(entry).encode()).hexdigest()


# ---------------------------------------------------------------- signatures (OpenSSH)
def _ssh_keygen(args, stdin=None):
    return subprocess.run(["ssh-keygen"] + args, input=stdin, capture_output=True, timeout=20)


def keygen(who):
    if not NAME.match(who):
        raise BatonError("agent names are lowercase letters, digits, - and _ (max 32)")
    os.makedirs(keys_dir(), mode=0o700, exist_ok=True)
    kp = key_path(who)
    if os.path.exists(kp):
        raise BatonError(f"{kp} already exists; refusing to overwrite a signing key")
    r = _ssh_keygen(["-q", "-t", "ed25519", "-N", "", "-C", f"{who}@{NAMESPACE}", "-f", kp])
    if r.returncode:
        raise BatonError("ssh-keygen failed: " + r.stderr.decode().strip())
    pub = open(kp + ".pub", encoding="utf-8").read().strip()
    os.makedirs(home(), exist_ok=True)
    with open(signers_path(), "a", encoding="utf-8") as f:
        f.write(f'{who} namespaces="{NAMESPACE}" {pub}\n')
    return kp


def sign(who, digest):
    kp = key_path(who)
    if not os.path.exists(kp):
        return None
    with tempfile.TemporaryDirectory() as d:
        msg = os.path.join(d, "m")
        with open(msg, "w") as f:
            f.write(digest)
        r = _ssh_keygen(["-Y", "sign", "-f", kp, "-n", NAMESPACE, msg])
        if r.returncode:
            raise BatonError("signing failed: " + r.stderr.decode().strip())
        return open(msg + ".sig", encoding="utf-8").read()


def check_sig(entry):
    """True/False for a signed entry; None if unsigned."""
    sig = entry.get("sig")
    if not sig:
        return None
    if not os.path.exists(signers_path()):
        return False
    with tempfile.TemporaryDirectory() as d:
        sp = os.path.join(d, "s")
        with open(sp, "w") as f:
            f.write(sig)
        r = _ssh_keygen(["-Y", "verify", "-f", signers_path(), "-I", entry["from"],
                         "-n", NAMESPACE, "-s", sp], stdin=entry["hash"].encode())
        return r.returncode == 0


# ---------------------------------------------------------------- ledger io
def load():
    if not os.path.exists(ledger_path()):
        return []
    out = []
    with open(ledger_path(), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def append(entry, require_sig=False):
    """Assign seq/prev/hash (and sig) under an exclusive lock and append."""
    os.makedirs(home(), exist_ok=True)
    with open(ledger_path(), "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            last = None
            for line in f:
                if line.strip():
                    last = line
            prev = json.loads(last) if last else None
            entry["seq"] = (prev["seq"] + 1) if prev else 1
            entry["prev"] = prev["hash"] if prev else GENESIS
            entry["hash"] = entry_hash(entry)
            sig = sign(entry["from"], entry["hash"])
            if sig:
                entry["sig"] = sig
            elif require_sig:
                raise BatonError(f"no signing key for {entry['from']} (run: baton keygen "
                                 f"--as {entry['from']}) and BATON_REQUIRE_SIG is set")
            f.seek(0, os.SEEK_END)
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return entry


def verify_chain(entries):
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        if e.get("seq") != i:
            return f"seq gap at line {i}: seq={e.get('seq')}"
        if e.get("prev") != prev:
            return f"broken chain at seq {i}: prev does not match seq {i - 1}"
        if entry_hash(e) != e.get("hash"):
            return f"hash mismatch at seq {i}: entry was edited"
        prev = e["hash"]
    return None


# ---------------------------------------------------------------- validation
#: The only acts that mark work: putting it up for approval (REQUEST) or reporting it
#: done (DONE). A GO by the author of one of these approves its own work (#14). Other
#: acts are not work: a verifier may reverse its own NOGO, or post review notes as an
#: INFORM naming the SHA before it approves. Work announced only as an INFORM is NOT
#: covered, so builders post each head for review as a REQUEST. A DONE that answers
#: ANOTHER agent's REQUEST naming the same SHA is a review result, not work (#29).
WORK_ACTS = {"REQUEST", "DONE"}


def _is_work(x, by, entries):
    """Whether entry ``x`` marks work by ``by`` (#14), not a review of someone else's (#29)."""
    if x["act"] not in WORK_ACTS or x["from"] != by:
        return False
    sha = (x.get("ref") or {}).get("sha")
    if x["act"] == "DONE" and sha:
        asked = next((y for y in entries if y["seq"] == x.get("re")), None)
        # Only a REQUEST asks for review: a DONE answering an INFORM or ACK stays work, or
        # anyone could launder work as a "review". (asked["from"] != by is masked by the
        # same-SHA scan, since your own REQUEST naming the SHA is work, but states intent.)
        if (asked and asked["act"] == "REQUEST" and asked["from"] != by
                and (asked.get("ref") or {}).get("sha") == sha):
            return False
    return True


def self_approval(e, entries):
    """Why GO ``e`` approves its own author's work, or None (#14).

    The work is the entry the GO answers (--re) and any earlier entry naming the same
    commit SHA, when that entry is a REQUEST or DONE. The author of a REQUEST counts as
    the work's author, so a GO on your own "please build X" is refused too.
    """
    if e["act"] != "GO":
        return None
    who, sha = e["from"], (e.get("ref") or {}).get("sha")
    target = next((x for x in entries if x["seq"] == e.get("re")), None)
    if target and _is_work(target, who, entries):
        return f"it answers #{target['seq']}, a {target['act']} by {who}"
    for x in entries:
        if (_is_work(x, who, entries) and sha
                and (x.get("ref") or {}).get("sha") == sha and x["seq"] < e.get("seq", 1 << 62)):
            return f"#{x['seq']}, a {x['act']} by {who}, names the same SHA"
    return None


def validate(e, entries):
    act = e["act"]
    if act not in ACTS:
        raise BatonError(f"unknown act {act}; one of {', '.join(ACTS)}")
    if not NAME.match(e["from"]):
        raise BatonError("--as must be a lowercase agent name")
    if not e["to"]:
        raise BatonError("--to needs at least one agent, or *")
    needs_re, needs_text = ACTS[act]
    if needs_re and not e.get("re"):
        raise BatonError(f"{act} must reply to an entry (--re SEQ)")
    if e.get("re") and not any(x["seq"] == e["re"] for x in entries):
        raise BatonError(f"--re {e['re']} does not exist")
    if needs_text and not e.get("text"):
        raise BatonError(f"{act} needs --text")
    ref, ev = e.get("ref", {}), e.get("evidence", {})
    if act in ("GO", "NOGO"):
        if not SHA40.match(ref.get("sha", "")):
            raise BatonError(f"{act} binds to an exact commit: --sha must be the full 40-hex SHA")
        if ref.get("pipeline") and ref.get("exception"):
            raise BatonError(f"{act} takes --pipeline or --exception, not both")
        if not ref.get("pipeline") and not ref.get("exception"):
            raise BatonError(f"{act} needs --pipeline (the CI run on that exact SHA), or "
                             "--exception (where the owner granted one) with --result")
        if ref.get("exception"):
            m = SEQREF.match(ref["exception"])
            if m and not any(x["seq"] == int(m.group(1)) for x in entries):
                raise BatonError(f"--exception {ref['exception']} does not exist")
            if not ev.get("result"):
                raise BatonError(
                    f"{act} with --exception needs --result: the evidence that replaced CI "
                    "(what ran, on which SHA, and its pass count)")
    if ref.get("digest") and not DIGEST.match(ref["digest"]):
        raise BatonError("--digest must be lowercase sha256:<64 hex> or sha512:<128 hex>")
    if act in ("GO", "FINDING"):
        if not ev.get("checked") or not ev.get("not_checked"):
            raise BatonError(
                f"{act} must state scope: at least one --checked AND one --not-checked "
                "(a verification claim without its limits is not accepted)")
    why = self_approval(e, entries)
    if why:
        raise BatonError(
            f"a GO must come from someone other than the author of the work it approves: "
            f"{why}. Ask another agent to verify. (Nothing is written for a refused post; "
            "'baton verify' lists self-approved GOs already on a ledger.)")
    if act == "FINDING" and not (ref.get("ticket") or ev.get("result")):
        raise BatonError("FINDING needs --ticket or --result")
    if act == "COUNT" and not ev.get("result"):
        raise BatonError("COUNT needs --result")


# ---------------------------------------------------------------- guardrail (monitor only)
def guard(text):
    """Screen the text with a content guardrail. Never blocks the post: the verdict is recorded.

    Either BATON_GUARD_CMD (a command that reads text on stdin and prints JSON with at least
    {"action": ...}), or BATON_GUARD_URL + BATON_GUARD_KEY (an HTTP endpoint shaped like
    POST /api/v1/guardrails/check). With neither set, entries are recorded as unchecked.
    """
    t0 = time.time()
    cmd = os.environ.get("BATON_GUARD_CMD")
    url, key = os.environ.get("BATON_GUARD_URL"), os.environ.get("BATON_GUARD_KEY")
    try:
        if cmd:
            r = subprocess.run(shlex.split(cmd), input=text.encode(), capture_output=True,
                               timeout=30)
            v = json.loads(r.stdout.decode() or "{}")
        elif url and key:
            req = urllib.request.Request(
                url.rstrip("/") + "/api/v1/guardrails/check",
                data=json.dumps({"input_text": text}).encode(),
                headers={"X-Api-Key": key, "content-type": "application/json"}, method="POST")
            res = json.loads(urllib.request.urlopen(req, timeout=20).read())
            v = res.get("input_result") or {}
            v = {"action": v.get("action"), "rails": v.get("rails_triggered") or [],
                 "unavailable": v.get("semantic_unavailable_reason")
                 or (v.get("semantic_unavailable") and "semantic_unavailable")}
        else:
            return {"action": "unchecked", "why": "no guard configured"}
    except Exception as exc:  # the ledger must not depend on the guard being up
        return {"action": "unchecked", "why": type(exc).__name__}
    out = {"action": v.get("action"), "rails": v.get("rails") or [],
           "ms": int((time.time() - t0) * 1000)}
    if v.get("unavailable"):
        # The guardrail could not actually judge the text (e.g. its model provider was
        # down) and failed closed. That's an outage, not a verdict on the message.
        out["unavailable"] = v["unavailable"]
    return out


def flagged(g):
    """A real would-have-blocked verdict, not a could-not-check."""
    return bool(g) and g.get("action") in FLAGGED and not g.get("unavailable")


# ---------------------------------------------------------------- views
def addressed_to(e, who):
    return "*" in e["to"] or who in e["to"]


def superseded(entries):
    return {e["re"]: e["seq"] for e in entries if e["act"] == "CORRECT"}


def render(e, sup=None, brief=False):
    sup = sup or {}
    ref, ev, g = e.get("ref", {}), e.get("evidence", {}), e.get("guard", {})
    head = f"#{e['seq']} {e['ts'][11:16]}Z {e['from']}→{','.join(e['to'])} {e['act']}"
    if e.get("re"):
        head += f" re#{e['re']}"
    if e.get("subject"):
        head += f" «{e['subject']}»"
    bits = []
    if ref.get("sha"):
        bits.append(f"sha={ref['sha'][:12]}")
    if ref.get("digest"):
        algo, _, hexd = ref["digest"].partition(":")
        bits.append(f"digest={algo}:{hexd[:12]}")
    for k in ("pipeline", "exception", "ticket", "mr", "artifact"):
        if ref.get(k):
            bits.append(f"{k}={ref[k]}")
    if bits:
        head += "  " + " ".join(bits)
    if not e.get("sig"):
        head += "  [unsigned]"
    if e["seq"] in sup:
        head += f"  [CORRECTED by #{sup[e['seq']]}]"
    if brief and e["act"] not in FULL_IN_BRIEF:
        if ev.get("not_checked"):
            head += "  [has not-checked]"
        if flagged(g):
            head += f"  [guard: {g.get('action')}]"
        return head
    lines = [head]
    if e.get("text"):
        lines += ["  " + ln for ln in e["text"].splitlines()]
    if ev.get("checked"):
        lines.append("  checked: " + "; ".join(ev["checked"]))
    if ev.get("not_checked"):
        lines.append("  NOT checked: " + "; ".join(ev["not_checked"]))
    for c in ev.get("test_cmd", []):
        lines.append(f"  test: {c}")
    if ev.get("n") or ev.get("result"):
        lines.append(f"  n={ev.get('n', '-')} result: {ev.get('result', '-')}")
    if flagged(g):
        lines.append(f"  guard: {g.get('action')} {g.get('rails') or ''}")
    elif g and g.get("unavailable"):
        lines.append(f"  guard: could not check ({g['unavailable']})")
    return "\n".join(lines)


def cursor_path(who):
    return os.path.join(home(), "cursors", f"{who}.json")


def get_cursor(who):
    try:
        return json.load(open(cursor_path(who)))["seq"]
    except Exception:
        return 0


def set_cursor(who, seq):
    os.makedirs(os.path.dirname(cursor_path(who)), exist_ok=True)
    tmp = cursor_path(who) + ".tmp"
    json.dump({"seq": seq}, open(tmp, "w"))
    os.replace(tmp, cursor_path(who))


# ---------------------------------------------------------------- commands
def cmd_keygen(a):
    kp = keygen(a.as_)
    print(f"key: {kp}\nregistered in: {signers_path()}")


def cmd_post(a):
    text = a.text
    if text == "-":
        text = sys.stdin.read().strip()
    e = {
        "v": VERSION,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from": a.as_,
        "to": [t.strip() for t in a.to.split(",") if t.strip()],
        "act": a.act.upper(),
    }
    if a.re:
        e["re"] = a.re
    if a.subject:
        e["subject"] = a.subject
    if text:
        e["text"] = text
    ref = {k: v.strip() for k, v in (("sha", a.sha), ("pipeline", a.pipeline),
                             ("exception", a.exception), ("ticket", a.ticket),
                             ("mr", a.mr), ("artifact", a.artifact),
                             ("digest", a.digest)) if v and v.strip()}
    if ref:
        e["ref"] = ref
    ev = {}
    if a.checked:
        ev["checked"] = a.checked
    if a.not_checked:
        ev["not_checked"] = a.not_checked
    if a.n:
        ev["n"] = a.n
    if a.result:
        ev["result"] = a.result
    cmds = [c.strip() for c in a.test_cmd or [] if c.strip()]
    if cmds:
        ev["test_cmd"] = cmds
    if ev:
        e["evidence"] = ev
    validate(e, load())
    if not a.no_guard:
        e["guard"] = guard(" ".join(x for x in (e.get("subject"), text) if x))
    e = append(e, require_sig=os.environ.get("BATON_REQUIRE_SIG") == "1")
    print(render(e))
    print(f"\ndoorbell: baton {e['seq']}")


def cmd_read(a):
    entries = load()
    cur = 0 if a.all else get_cursor(a.as_)
    sup = superseded(entries)
    new = [e for e in entries
           if e["seq"] > cur and e["from"] != a.as_ and addressed_to(e, a.as_)]
    for e in new:
        out = render(e, sup, brief=a.brief)
        print(out + ("\n" if not a.brief or "\n" in out else ""))
    if not new:
        print(f"(nothing new for {a.as_} after #{cur})")
    if entries and not a.peek:
        set_cursor(a.as_, entries[-1]["seq"])


def cmd_open(a):
    entries = load()
    closed = {e["re"] for e in entries if e["act"] in CLOSERS and e["from"] == a.as_}
    sup = superseded(entries)
    reqs = [e for e in entries if e["act"] == "REQUEST" and addressed_to(e, a.as_)
            and e["from"] != a.as_ and e["seq"] not in closed]
    for e in reqs:
        print(render(e, sup) + "\n")
    if not reqs:
        print(f"(no open requests for {a.as_})")


def cmd_show(a):
    entries = {e["seq"]: e for e in load()}
    sup = superseded(list(entries.values()))
    for s in a.seq:
        print(render(entries[s], sup) if s in entries else f"#{s}: no such entry")


def cmd_thread(a):
    entries = load()
    by = {e["seq"]: e for e in entries}
    if a.seq not in by:
        raise BatonError(f"#{a.seq}: no such entry")
    root = a.seq
    while by.get(root, {}).get("re"):
        root = by[root]["re"]
    members, frontier = {root}, [root]
    while frontier:
        s = frontier.pop()
        for e in entries:
            if e.get("re") == s and e["seq"] not in members:
                members.add(e["seq"])
                frontier.append(e["seq"])
    sup = superseded(entries)
    for s in sorted(members):
        print(render(by[s], sup) + "\n")


def cmd_tail(a):
    entries = load()
    sup = superseded(entries)
    for e in entries[-a.n:]:
        print(render(e, sup) + "\n")


def cmd_verify(a):
    entries = load()
    err = verify_chain(entries)
    if err:
        print("BROKEN: " + err)
        sys.exit(1)
    bad, unsigned = [], []
    for e in entries:
        ok = check_sig(e)
        if ok is None:
            unsigned.append(e["seq"])
        elif not ok:
            bad.append(e["seq"])
    hits = [e["seq"] for e in entries if flagged(e.get("guard"))]
    selfgo = [e["seq"] for e in entries if self_approval(e, entries[: e["seq"] - 1])]
    outages = [e["seq"] for e in entries if (e.get("guard") or {}).get("unavailable")]
    print(f"chain: intact ({len(entries)} entries)")
    print(f"signatures: {len(entries) - len(bad) - len(unsigned)} good, "
          f"{len(bad)} BAD {bad or ''}, {len(unsigned)} unsigned {unsigned or ''}")
    print(f"guard would have blocked or modified: {hits or 'none'}"
          + (f"; could not check: {outages}" if outages else ""))
    print(f"self-approved GOs: {selfgo or 'none'}")
    if bad or (a.strict and unsigned):
        sys.exit(1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="baton", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"baton {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create and register an Ed25519 signing key for an agent")
    s.add_argument("--as", dest="as_", required=True)
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("post", help="append an entry")
    s.add_argument("--as", dest="as_", required=True)
    s.add_argument("--to", required=True, help="comma list of agents, or *")
    s.add_argument("--act", required=True, help=", ".join(ACTS))
    s.add_argument("--re", type=int)
    s.add_argument("--subject")
    s.add_argument("--text", help="message text, or - to read stdin")
    s.add_argument("--sha")
    s.add_argument("--pipeline")
    s.add_argument("--exception", help="GO/NOGO without CI: the entry (#N) or ticket where "
                   "the owner granted the exception; needs --result")
    s.add_argument("--ticket")
    s.add_argument("--mr")
    s.add_argument("--artifact", help="path or URL to supporting evidence")
    s.add_argument("--digest", help="sha256:<hex> (or sha512:<hex>) of the built file a GO approves")
    s.add_argument("--checked", action="append")
    s.add_argument("--not-checked", dest="not_checked", action="append")
    s.add_argument("--n", type=int)
    s.add_argument("--result")
    s.add_argument("--test-cmd", dest="test_cmd", action="append",
                   help="the exact test command run (repeatable); recorded, not re-run")
    s.add_argument("--no-guard", action="store_true")
    s.set_defaults(fn=cmd_post)

    for name, fn, h in (("read", cmd_read, "show what is new for an agent"),
                        ("open", cmd_open, "list REQUESTs an agent has not closed")):
        s = sub.add_parser(name, help=h)
        s.add_argument("--as", dest="as_", required=True)
        if name == "read":
            s.add_argument("--all", action="store_true")
            s.add_argument("--peek", action="store_true", help="don't advance the cursor")
            s.add_argument("--brief", action="store_true",
                           help="one line per entry (GO/NOGO/FINDING/CORRECT stay in full); "
                                "'show N' prints the rest")
        s.set_defaults(fn=fn)

    s = sub.add_parser("show")
    s.add_argument("seq", type=int, nargs="+")
    s.set_defaults(fn=cmd_show)
    s = sub.add_parser("thread")
    s.add_argument("seq", type=int)
    s.set_defaults(fn=cmd_thread)
    s = sub.add_parser("tail")
    s.add_argument("-n", type=int, default=10)
    s.set_defaults(fn=cmd_tail)
    s = sub.add_parser("verify", help="check the hash chain and every signature")
    s.add_argument("--strict", action="store_true", help="also fail on unsigned entries")
    s.set_defaults(fn=cmd_verify)

    a = p.parse_args(argv)
    try:
        a.fn(a)
    except BatonError as exc:
        print(f"baton: refused: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
