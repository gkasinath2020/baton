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
    baton open --as assay          # REQUESTs to assay that assay hasn't closed (+ ACK status)
    baton waiting --as forge       # forge's own REQUESTs nobody has closed (+ ACK status)
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

__version__ = "1.10.0"

VERSION = 1
GENESIS = "0" * 64
NAMESPACE = "baton"
#: Entries an app posts through baton_mcp.py carry ``via: "mcp"`` and are signed with the
#: agent's separate app key, registered for this namespace only. OpenSSH refuses to verify
#: such a signature as an ordinary ``baton`` one, so a leaked app key can't sign a CLI entry.
MCP_NAMESPACE = "baton-mcp"
#: What an app may post. Approvals (GO, NOGO), closers (DONE, DECLINE) and CORRECT, which
#: can supersede a GO, stay CLI-only (#30).
MCP_ACTS = {"INFORM", "REQUEST", "ACK", "FINDING", "COUNT"}

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
#: A reviewer's verdict on a REQUEST also answers it (#37): a GO or NOGO anywhere in the
#: REQUEST's reply thread closes it in ``open`` and ``waiting``, as a DONE or DECLINE does.
#: Views only: closing never makes a GO valid (that is ``check-go``), and an entry with no
#: ``--re`` closes nothing.
VERDICTS = {"GO", "NOGO"}
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


def key_path(who, mcp=False):
    return os.path.join(keys_dir(), who + (".mcp" if mcp else ""))


def entry_namespace(entry):
    return MCP_NAMESPACE if entry.get("via") == "mcp" else NAMESPACE


# ---------------------------------------------------------------- hashing
def _canon(entry):
    body = {k: v for k, v in entry.items() if k not in ("hash", "sig")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry):
    return hashlib.sha256(_canon(entry).encode()).hexdigest()


# ---------------------------------------------------------------- signatures (OpenSSH)
def _ssh_keygen(args, stdin=None):
    return subprocess.run(["ssh-keygen"] + args, input=stdin, capture_output=True, timeout=20)


def keygen(who, mcp=False):
    if not NAME.match(who):
        raise BatonError("agent names are lowercase letters, digits, - and _ (max 32)")
    os.makedirs(keys_dir(), mode=0o700, exist_ok=True)
    kp = key_path(who, mcp)
    ns = MCP_NAMESPACE if mcp else NAMESPACE
    if os.path.exists(kp):
        raise BatonError(f"{kp} already exists; refusing to overwrite a signing key")
    r = _ssh_keygen(["-q", "-t", "ed25519", "-N", "", "-C", f"{who}@{ns}", "-f", kp])
    if r.returncode:
        raise BatonError("ssh-keygen failed: " + r.stderr.decode().strip())
    pub = open(kp + ".pub", encoding="utf-8").read().strip()
    os.makedirs(home(), exist_ok=True)
    with open(signers_path(), "a", encoding="utf-8") as f:
        f.write(f'{who} namespaces="{ns}" {pub}\n')
    return kp


def sign(who, digest, mcp=False):
    kp = key_path(who, mcp)
    if not os.path.exists(kp):
        return None
    with tempfile.TemporaryDirectory() as d:
        msg = os.path.join(d, "m")
        with open(msg, "w") as f:
            f.write(digest)
        r = _ssh_keygen(["-Y", "sign", "-f", kp, "-n", MCP_NAMESPACE if mcp else NAMESPACE,
                         msg])
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
                         "-n", entry_namespace(entry), "-s", sp],
                        stdin=entry["hash"].encode())
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
            mcp = entry.get("via") == "mcp"
            sig = sign(entry["from"], entry["hash"], mcp=mcp)
            if sig:
                entry["sig"] = sig
            elif mcp:
                raise BatonError(f"no app key for {entry['from']} (run: baton keygen --mcp "
                                 f"--as {entry['from']}); an app entry is never unsigned")
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
    if "via" in e and e["via"] != "mcp":
        raise BatonError("via, if present, must be \"mcp\"")
    if e.get("via") == "mcp" and act not in MCP_ACTS:
        raise BatonError(f"an app may not post {act}: apps post only "
                         f"{', '.join(sorted(MCP_ACTS))}; {act} stays on the CLI")
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
    by = {x["seq"]: x for x in entries}
    for c in ev.get("carried", []):
        src = by.get(c["from"])
        if not src:
            raise BatonError(f"--carried {c['from']}.{c['k']}: entry #{c['from']} does not exist")
        if not 1 <= c["k"] <= len(claims(src)):
            raise BatonError(f"--carried {c['from']}.{c['k']}: #{c['from']} has "
                             f"{len(claims(src))} claim(s) (its checked items, then carried)")
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


# ---------------------------------------------------------------- carried claims (#23)
CLAIM_ID = re.compile(r"^#?(\d+)\.(\d+)$")


def claims(e):
    """Entry e's claims, in a fixed order: its ``checked`` items, then its carried ones.

    Claim ``#N.k`` is the k-th (1-based). Entries are append-only, so an id is never reused
    or renumbered; a correction is a new entry with new ids.
    """
    ev = e.get("evidence", {})
    return ([("checked", c) for c in ev.get("checked", [])]
            + [("carried", c) for c in ev.get("carried", [])])


def claim_path(seq, k, by):
    """The hops from claim #seq.k back to the entry that checked it: [(seq, k), ...]."""
    path, seen = [], set()
    while (seq, k) not in seen:
        seen.add((seq, k))
        path.append((seq, k))
        cl = claims(by[seq]) if seq in by else []
        if not 1 <= k <= len(cl):
            break
        kind, c = cl[k - 1]
        if kind == "checked":
            break
        seq, k = c["from"], c["k"]
    return path


def carry_note(c, carrier, entries, sup, now=None):
    """One display line for a carried claim: what it is, where from, how old, and whether a
    source on its path was CORRECTed (#23). A carried claim never renders as fresh."""
    now = now or datetime.now(timezone.utc)
    by = {e["seq"]: e for e in entries}
    path = claim_path(c["from"], c["k"], by)
    root_seq, root_k = path[-1]
    root = by.get(root_seq)
    cl = claims(root) if root else []
    text = cl[root_k - 1][1] if 1 <= root_k <= len(cl) and cl[root_k - 1][0] == "checked" \
        else "(claim not found)"
    # Runs: the carrier's own entries after the source, not counting this carry (#2318).
    runs = sum(1 for e in entries if e["from"] == carrier["from"] and e["seq"] > root_seq
               and e["seq"] != carrier["seq"])
    line = (f"  carried #{c['from']}.{c['k']} \"{text}\""
            + (f" (via {' <- '.join(f'#{s}.{k}' for s, k in path[1:])})" if len(path) > 1 else "")
            + f" from {root['from'] if root else '?'}, not re-verified"
            + f" · {runs} run{'s' if runs != 1 else ''} · "
            + (_ago(root["ts"], now) if root else "?"))
    # Every CORRECT of every entry on the path, each named with its poster (Assay #2309,
    # #2318). Local map, not superseded(): that keeps only the last CORRECT per entry.
    fixes = {}
    for x in entries:
        if x["act"] == "CORRECT" and x.get("re"):
            fixes.setdefault(x["re"], []).append(x["seq"])
    who = lambda x: by[x]["from"] if x in by else "?"  # noqa: E731
    hits = []
    for s, _ in path:
        for c in fixes.get(s, []):
            # Any agent may CORRECT (SPEC). A CORRECT of a CORRECT can't tell withdrawn from
            # replaced, so the line says only what the ledger shows and never turns clean.
            when = "after" if c > carrier["seq"] else "before"
            note = f"#{s} corrected (#{c} by {who(c)}, {when} this carry)"
            seen, stack = {c}, [c]
            while stack:
                parent = stack.pop(0)
                for d in fixes.get(parent, []):
                    if d not in seen:
                        seen.add(d)
                        stack.append(d)
                        note += f"; #{parent} itself corrected (#{d} by {who(d)})"
            hits.append(note)
    if hits:
        line += "\n    source corrected: " + " | ".join(hits) + ". Re-verify before relying on it."
    return line


def render(e, sup=None, brief=False, entries=None):
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
    if e.get("via"):
        head += f"  [via {e['via']}]"
    if not e.get("sig"):
        head += "  [unsigned]"
    if e["seq"] in sup:
        head += f"  [CORRECTED by #{sup[e['seq']]}]"
    if brief and e["act"] not in FULL_IN_BRIEF:
        if ev.get("not_checked"):
            head += "  [has not-checked]"
        if ev.get("carried"):
            head += "  [has carried]"
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
    for c in ev.get("carried", []):
        lines.append(carry_note(c, e, entries, sup) if entries is not None
                     else f"  carried #{c['from']}.{c['k']}, not re-verified")
    for c in ev.get("test_cmd", []):
        lines.append(f"  test: {c}")
    if ev.get("n") or ev.get("result"):
        lines.append(f"  n={ev.get('n', '-')} result: {ev.get('result', '-')}")
    if flagged(g):
        lines.append(f"  guard: {g.get('action')} {g.get('rails') or ''}")
    elif g and g.get("unavailable"):
        lines.append(f"  guard: could not check ({g['unavailable']})")
    return "\n".join(lines)


# ---------------------------------------------------------------- request status (#31)
def _parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _ago(ts, now):
    secs = max(0, int((now - _parse_ts(ts)).total_seconds()))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return "just now"


def _thread_of(seq, entries):
    """seq and every entry that replies to it, directly or through other replies."""
    members, frontier = {seq}, [seq]
    while frontier:
        s = frontier.pop()
        for e in entries:
            if e.get("re") == s and e["seq"] not in members:
                members.add(e["seq"])
                frontier.append(e["seq"])
    return members


def _closed_by(entries, poster_ok):
    """Seqs of REQUESTs closed by a DONE, DECLINE, GO or NOGO in their reply thread (#37).

    The answer often replies to a later entry in the thread ("pipeline green, GO on
    that"), not to the REQUEST itself, so the answer closes the NEAREST REQUEST above it in
    the reply chain, and only that one: answering a nested sub-request doesn't close the
    request it hangs off. ``poster_ok(e)`` says whose answers count for this view.
    """
    by = {e["seq"]: e for e in entries}
    closed = set()
    for e in entries:
        if not e.get("re") or e["act"] not in CLOSERS | VERDICTS or not poster_ok(e):
            continue
        seen, s = set(), e["re"]
        while s in by and s not in seen:
            seen.add(s)
            if by[s]["act"] == "REQUEST":
                closed.add(s)
                break
            s = by[s].get("re")
    return closed


def open_requests(who, entries):
    """REQUESTs addressed to ``who`` that ``who`` has not closed (what ``who`` owes)."""
    closed = _closed_by(entries, lambda e: e["from"] == who)
    return [e for e in entries if e["act"] == "REQUEST" and addressed_to(e, who)
            and e["from"] != who and e["seq"] not in closed]


def waiting_requests(who, entries):
    """``who``'s own REQUESTs that nobody else has closed (what ``who`` is waiting on)."""
    closed = _closed_by(entries, lambda e: e["from"] != who)
    return [e for e in entries if e["act"] == "REQUEST" and e["from"] == who
            and e["seq"] not in closed]


def request_status(req, entries, now=None):
    """Who has ACKed an open REQUEST, and how old its thread's newest entry is (#31).

    An ACK followed by nothing is the silent-abandonment case: the age of the newest
    entry in the thread makes it visible. Nothing expires; a reader decides.
    """
    now = now or datetime.now(timezone.utc)
    acks = [e for e in entries if e["act"] == "ACK" and e.get("re") == req["seq"]
            and e["from"] != req["from"]]
    thread = _thread_of(req["seq"], entries)
    newest = max((e for e in entries if e["seq"] in thread), key=lambda e: e["seq"])
    if acks:
        ack = ", ".join(f"{e['from']} {_ago(e['ts'], now)}" for e in acks)
        head = f"acked by {ack}"
    else:
        head = "not acked"
    last = ("nothing since the request" if newest["seq"] == req["seq"]
            else f"last activity #{newest['seq']} by {newest['from']} {_ago(newest['ts'], now)}")
    return f"[{head}; {last}]"


def cursor_path(who):
    return os.path.join(home(), "cursors", f"{who}.json")


def get_witness(who):
    """The highest entry ``who`` has read: ``(seq, hash)``, or ``(0, None)`` the first time (#3).

    A missing cursor file means a first-ever read. A file that exists but can't be parsed is
    NOT treated the same way: resetting it to 0 would erase the witness, so it raises.
    ``hash`` is None for cursors written before #3; the next advance records it.
    """
    path = cursor_path(who)
    if not os.path.exists(path):
        return 0, None
    try:
        with open(path) as f:
            c = json.load(f)
        seq, h = c["seq"], c.get("hash")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError(f"seq={seq!r}")
        if h is not None and not isinstance(h, str):
            raise ValueError(f"hash={h!r}")
    except Exception as exc:
        raise BatonError(f"cursor for {who} is malformed ({path}: {exc}); refusing to reset it "
                         "to 0, which would erase the record of what it has read. "
                         "Inspect it before deleting it.") from exc
    return seq, h


def get_cursor(who):
    return get_witness(who)[0]


def witness_error(who, entries, witness=None):
    """Why ``entries`` contradict what ``who`` has already read, or None (#3).

    ``witness`` must be read BEFORE ``entries`` were loaded (Assay #2308): the ledger is
    append-only, so a ledger loaded after the cursor is never shorter than it unless the
    tail really was cut. Read the other way round, a concurrent post + read makes a healthy
    ledger look truncated. Detects a tail truncated or rewritten below the reader's cursor;
    it cannot detect the cursor and the ledger rolled back together (one trust domain).
    """
    seq, h = witness if witness is not None else get_witness(who)
    if seq > len(entries):
        return (f"{who} has read up to #{seq} but the ledger ends at #{len(entries)}: "
                "the tail was truncated")
    if seq and h and entries[seq - 1].get("hash") != h:
        return f"entry #{seq} no longer has the hash {who} read: the tail was rewritten"
    return None


def check_witness(who, entries, witness):
    err = witness_error(who, entries, witness)
    if err:
        raise BatonError(err + ". Not moving the cursor; run `baton verify` and have a "
                         "human look before acting on this ledger.")


def load_witnessed(who, doorbell=None):
    """``(witness, entries)``: the cursor and doorbell witness read first, then the ledger,
    then both checked (#3). ``doorbell`` (text as pasted) is checked and recorded too."""
    witness = get_witness(who)
    bell = get_bell(who)  # #3 S2: also read before the ledger
    pairs = parse_doorbell(doorbell) if doorbell else []
    entries = load()
    check_witness(who, entries, witness)
    ring(who, pairs, entries, bell)
    return witness, entries


def advance_cursor(who, entries):
    """Move ``who``'s cursor to the tail of ``entries``, never backwards (#3).

    Re-reads the cursor first: if a concurrent read already moved it to or past this tail,
    it is left alone. No witness check here: ``entries`` may be older than that cursor.
    """
    if not entries or get_cursor(who) >= entries[-1]["seq"]:
        return
    set_cursor(who, entries[-1]["seq"], entries[-1]["hash"])


def set_cursor(who, seq, h=None):
    os.makedirs(os.path.dirname(cursor_path(who)), exist_ok=True)
    tmp = cursor_path(who) + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"seq": seq, "hash": h} if h else {"seq": seq}, f)
    os.replace(tmp, cursor_path(who))


# ---------------------------------------------------------------- doorbell witness (#3 S2)
#: A doorbell names the head it was rung from: "baton N <first 16+ hex of entry N's hash>".
BELL_HASH = re.compile(r"^[0-9a-f]{16,64}$")


def witness_dir():
    """Where recipients keep what doorbells told them: OUTSIDE the ledger directory, so a
    trim of that directory (ledger and cursors rolled back together) is still caught."""
    return os.environ.get("BATON_WITNESS", os.path.expanduser("~/.baton/witness"))


def ledger_id():
    """Per-ledger key for witnesses: the ledger directory's real path, hashed. Not entry 1's
    hash, which a rewrite from the start would change, silently dropping the witness."""
    return hashlib.sha256(os.path.realpath(home()).encode()).hexdigest()[:16]


def genesis_id(entries):
    """Which ledger this is: the first entry's hash. Stored in each witness, so a ledger
    regenerated from genesis at the same path is caught, not read as a first bell."""
    return entries[0]["hash"][:16] if entries else "empty"


def where(entries):
    return f"ledger {os.path.realpath(home())} (genesis {genesis_id(entries)})"


def bell_path(who):
    return os.path.join(witness_dir(), ledger_id(), f"{who}.json")


def get_bell(who, path=None):
    """The highest ``(seq, hash prefix)`` a doorbell told ``who``, or None (#3 S2)."""
    path = path or bell_path(who)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            b = json.load(f)
        seq, h, g = b["seq"], b["hash"], b["genesis"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 \
                or not isinstance(h, str) or not BELL_HASH.match(h) or not isinstance(g, str):
            raise ValueError(f"seq={seq!r} hash={h!r} genesis={g!r}")
    except Exception as exc:
        raise BatonError(f"doorbell witness for {who} is malformed ({path}: {exc}); not "
                         "treating it as empty. Inspect it before deleting it.") from exc
    return seq, h, g


def bell_error(who, entries, bell):
    """Why ``entries`` contradict a doorbell ``who`` was given, or None. Every message names
    the ledger path and genesis it checked, so a wrong BATON_HOME (Assay, 31 Oct) can be
    told apart from a cut tail (Assay #2324)."""
    if bell is None:
        return None
    seq, h, g = bell
    if g != genesis_id(entries):
        return (f"{where(entries)} is not the ledger {who} was rung from (genesis {g}): "
                "it was regenerated, or this is the wrong BATON_HOME")
    if seq > len(entries):
        return (f"a doorbell told {who} about #{seq} but {where(entries)} ends at "
                f"#{len(entries)}: the tail was truncated after the bell rang, or this is the "
                "wrong BATON_HOME")
    if not entries[seq - 1].get("hash", "").startswith(h):
        return (f"entry #{seq} of {where(entries)} no longer matches the hash its doorbell "
                f"gave {who}: the tail was rewritten after the bell rang")
    return None


def set_bell(who, seq, h, g):
    path = bell_path(who)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"seq": seq, "hash": h, "genesis": g, "ledger": os.path.realpath(home())},
                  f)
    os.replace(tmp, path)


def bell_witnesses():
    """Every recipient's doorbell witness for this ledger, read now (for verify)."""
    d = os.path.join(witness_dir(), ledger_id())
    out = {}
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if name.endswith(".json"):
            try:
                out[name[:-5]] = get_bell(name[:-5], os.path.join(d, name))
            except BatonError as exc:
                out[name[:-5]] = str(exc)
    return out


def cursor_witnesses():
    """Every reader's cursor, read now: {who: witness or the BatonError text} (#3)."""
    d = os.path.join(home(), "cursors")
    out = {}
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if name.endswith(".json"):
            try:
                out[name[:-5]] = get_witness(name[:-5])
            except BatonError as exc:
                out[name[:-5]] = str(exc)
    return out


def cursor_witness_errors(witnesses, entries):
    """Cursors snapshotted BEFORE ``entries`` were loaded, checked against them (#3)."""
    errs = []
    for who, w in witnesses.items():
        err = w if isinstance(w, str) else witness_error(who, entries, w)
        if err:
            errs.append(err)
    return errs


# ---------------------------------------------------------------- commands
def cmd_keygen(a):
    kp = keygen(a.as_, mcp=a.mcp)
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
    if a.carried:
        ev["carried"] = []
        for c in a.carried:
            m = CLAIM_ID.match(c.strip())
            if not m:
                raise BatonError(f"--carried {c!r}: name a claim as N.k (entry N, its k-th claim)")
            ev["carried"].append({"from": int(m.group(1)), "k": int(m.group(2))})
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
    print(f"\ndoorbell: {doorbell(e)}")


def doorbell(e):
    """What to send the recipients: the entry number and its hash, so each can witness it."""
    return f"baton {e['seq']} {e['hash'][:16]}"


def parse_doorbell(text):
    """``[(seq, hash), ...]`` from doorbell text as pasted (Assay #2324): 'baton 12 ab..',
    'baton 2308, 2309 <h> <h>' (numbers, then their hashes in order). An old doorbell with
    no hashes gives []; numbers and hashes that don't pair up are an error."""
    nums, hashes = [], []
    for tok in re.split(r"[\s,;]+", text.strip().lower()):
        if not tok or tok == "baton":
            continue
        if re.fullmatch(r"#?\d{1,15}", tok):
            nums.append(int(tok.lstrip("#")))
        elif BELL_HASH.match(tok):
            hashes.append(tok)
        else:
            raise BatonError(f"can't read {tok!r} in doorbell {text!r}: expected entry numbers "
                             "and 16-64 hex hashes")
    if hashes and len(hashes) != len(nums):
        raise BatonError(f"doorbell {text!r} has {len(nums)} number(s) but {len(hashes)} "
                         "hash(es); can't pair them")
    return list(zip(nums, hashes))


def ring(who, pairs, entries, old):
    """Check every (seq, hash) against ``entries`` and the current witness ``old`` (read
    before ``entries``); record the highest. Nothing is recorded if any check fails."""
    g = genesis_id(entries)
    for seq, h in [(None, None)] + pairs:
        err = bell_error(who, entries, old if seq is None else (seq, h, g))
        if err:
            raise BatonError(err + ". Nothing recorded; have a human look before acting on it.")
    if not pairs:
        return old
    seq, h = max(pairs)
    if old is None or seq > old[0]:
        set_bell(who, seq, h, g)
        return seq, h, g
    return old


def cmd_bell(a):
    """Check a doorbell against the ledger and keep the highest one, outside the ledger
    directory (#3 S2)."""
    old = get_bell(a.as_)
    pairs = parse_doorbell(" ".join(a.doorbell))
    if not pairs:
        raise BatonError("this doorbell has no hash to check (an old-style 'baton N')")
    entries = load()
    now = ring(a.as_, pairs, entries, old)
    print(f"ok: {', '.join(f'#{n}' for n, _ in pairs)} match their doorbell in "
          f"{where(entries)}; {a.as_}'s witness is #{now[0]}")


def cmd_read(a):
    witness, entries = load_witnessed(a.as_, a.bell)  # #3: before printing anything
    cur = 0 if a.all else witness[0]
    sup = superseded(entries)
    new = [e for e in entries
           if e["seq"] > cur and e["from"] != a.as_ and addressed_to(e, a.as_)]
    for e in new:
        out = render(e, sup, brief=a.brief, entries=entries)
        print(out + ("\n" if not a.brief or "\n" in out else ""))
    if not new:
        print(f"(nothing new for {a.as_} after #{cur})")
    if not a.peek:
        advance_cursor(a.as_, entries)


def cmd_open(a):
    entries = load()
    sup = superseded(entries)
    reqs = [e for e in open_requests(a.as_, entries) if e["seq"] >= a.since]
    for e in reqs:
        print(render(e, sup, entries=entries) + "\n  " + request_status(e, entries) + "\n")
    if not reqs:
        print(f"(no open requests for {a.as_})")


def cmd_waiting(a):
    entries = load()
    sup = superseded(entries)
    reqs = [e for e in waiting_requests(a.as_, entries) if e["seq"] >= a.since]
    for e in reqs:
        print(render(e, sup, entries=entries) + "\n  " + request_status(e, entries) + "\n")
    if not reqs:
        print(f"(nothing {a.as_} asked for is still open)")


def cmd_show(a):
    ledger = load()
    entries = {e["seq"]: e for e in ledger}
    sup = superseded(ledger)
    for s in a.seq:
        print(render(entries[s], sup, entries=ledger) if s in entries
              else f"#{s}: no such entry")


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
        print(render(by[s], sup, entries=entries) + "\n")


def cmd_tail(a):
    entries = load()
    sup = superseded(entries)
    for e in entries[-a.n:]:
        print(render(e, sup, entries=entries) + "\n")


def cmd_verify(a):
    witnesses = cursor_witnesses()  # #3: cursors first, then the ledger (Assay #2308)
    bells = bell_witnesses()
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
    app = [e["seq"] for e in entries if e.get("via") == "mcp"]
    app_bad = [e["seq"] for e in entries if e.get("via") == "mcp" and e["act"] not in MCP_ACTS]
    print(f"chain: intact ({len(entries)} entries)")
    print(f"signatures: {len(entries) - len(bad) - len(unsigned)} good, "
          f"{len(bad)} BAD {bad or ''}, {len(unsigned)} unsigned {unsigned or ''}")
    print(f"guard would have blocked or modified: {hits or 'none'}"
          + (f"; could not check: {outages}" if outages else ""))
    print(f"self-approved GOs: {selfgo or 'none'}")
    print(f"app-posted (via mcp): {app or 'none'}"
          + (f"; WITH A REFUSED ACT: {app_bad}" if app_bad else ""))
    cur_errs = cursor_witness_errors(witnesses, entries)
    bell_errs = []
    for who, b in bells.items():
        err = b if isinstance(b, str) else bell_error(who, entries, b)
        if err:
            bell_errs.append(err)
    print("cursors: " + ("; ".join(f"BROKEN: {x}" for x in cur_errs) if cur_errs
                         else "consistent with the ledger"))
    bdir = os.path.join(witness_dir(), ledger_id())
    print(f"doorbell witnesses in {bdir}: "
          + (", ".join(sorted(bells)) if bells else "none")
          + ("; " + "; ".join(f"BROKEN: {x}" for x in bell_errs) if bell_errs else ""))
    if bad or app_bad or cur_errs or bell_errs or (a.strict and unsigned):
        sys.exit(1)


def check_go(seq, sha, entries, signer=None):
    """Why GO #seq must NOT be acted on for ``sha``, or None if it may (#30, consumers).

    Act on a GO only if it is a GO, posted from the CLI (no ``via``), validly signed in the
    ``baton`` namespace by its named sender (unsigned is refused too: anyone who can write
    the file can append a raw line), names exactly this SHA, carries a pipeline or an
    exception, is not self-approved, and has not been CORRECTed.
    """
    err = verify_chain(entries)
    if err:
        return "ledger chain is broken: " + err
    by = {e["seq"]: e for e in entries}
    e = by.get(seq)
    if not e:
        return f"#{seq}: no such entry"
    if e["act"] != "GO":
        return f"#{seq} is a {e['act']}, not a GO"
    if e.get("via"):
        return f"#{seq} was posted by an app (via {e['via']}); apps cannot approve"
    if signer and e["from"] != signer:
        return f"#{seq} is from {e['from']}, not {signer}"
    ok = check_sig(e)
    if ok is None:
        return f"#{seq} is unsigned"
    if not ok:
        return f"#{seq} has a BAD signature for {e['from']}"
    if (e.get("ref") or {}).get("sha") != sha:
        return f"#{seq} approves {(e.get('ref') or {}).get('sha')}, not {sha}"
    ref = e.get("ref") or {}
    if not ref.get("pipeline") and not ref.get("exception"):
        return f"#{seq} names no pipeline or exception"
    why = self_approval(e, entries[: seq - 1])
    if why:
        return f"#{seq} is self-approved: {why}"
    if seq in superseded(entries):
        return f"#{seq} was CORRECTed by #{superseded(entries)[seq]}"
    return None


def cmd_check_go(a):
    why = check_go(a.seq, a.sha, load(), signer=a.signer)
    if why:
        print(f"DO NOT ACT: {why}")
        sys.exit(1)
    print(f"OK: #{a.seq} is a signed CLI GO for {a.sha}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="baton", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"baton {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create and register an Ed25519 signing key for an agent")
    s.add_argument("--as", dest="as_", required=True)
    s.add_argument("--mcp", action="store_true",
                   help="the agent's separate APP key for baton_mcp.py (namespace baton-mcp)")
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
    s.add_argument("--carried", action="append", metavar="N.k",
                   help="relay claim k of entry N without re-verifying it (#23); repeatable")
    s.add_argument("--n", type=int)
    s.add_argument("--result")
    s.add_argument("--test-cmd", dest="test_cmd", action="append",
                   help="the exact test command run (repeatable); recorded, not re-run")
    s.add_argument("--no-guard", action="store_true")
    s.set_defaults(fn=cmd_post)

    for name, fn, h in (("read", cmd_read, "show what is new for an agent"),
                        ("open", cmd_open, "list REQUESTs an agent has not closed, with "
                                           "ACK status"),
                        ("waiting", cmd_waiting, "list an agent's own REQUESTs nobody has "
                                                 "closed, with ACK status")):
        s = sub.add_parser(name, help=h)
        s.add_argument("--as", dest="as_", required=True)
        if name in ("open", "waiting"):
            s.add_argument("--since", type=int, default=0, metavar="N",
                           help="only requests at entry N or later (hide older history)")
        if name == "read":
            s.add_argument("--all", action="store_true")
            s.add_argument("--peek", action="store_true", help="don't advance the cursor")
            s.add_argument("--bell", metavar="DOORBELL",
                           help="the doorbell as pasted ('baton N HASH ...'): checked and "
                                "remembered before reading (#3)")
            s.add_argument("--brief", action="store_true",
                           help="one line per entry (GO/NOGO/FINDING/CORRECT stay in full); "
                                "'show N' prints the rest")
        s.set_defaults(fn=fn)

    s = sub.add_parser("bell", help="check a doorbell ('baton N HASH') against the ledger and "
                       "remember the highest one, outside the ledger dir (#3)")
    s.add_argument("--as", dest="as_", required=True)
    s.add_argument("doorbell", nargs="+", help="the doorbell as pasted, e.g. baton 12 3fa9c1...")
    s.set_defaults(fn=cmd_bell)

    s = sub.add_parser("show")
    s.add_argument("seq", type=int, nargs="+")
    s.set_defaults(fn=cmd_show)
    s = sub.add_parser("thread")
    s.add_argument("seq", type=int)
    s.set_defaults(fn=cmd_thread)
    s = sub.add_parser("tail")
    s.add_argument("-n", type=int, default=10)
    s.set_defaults(fn=cmd_tail)
    s = sub.add_parser("check-go", help="exit 0 only if GO #N may be acted on for --sha "
                       "(signed CLI GO, exact SHA, not self-approved, not corrected)")
    s.add_argument("seq", type=int)
    s.add_argument("--sha", required=True)
    s.add_argument("--from", dest="signer", help="the agent whose GO you expect")
    s.set_defaults(fn=cmd_check_go)
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
