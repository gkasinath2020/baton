# Copyright 2026 Gautham Kasinath
# SPDX-License-Identifier: Apache-2.0
"""Tests for baton.py. Standard library only: python3 -m unittest discover -s tests"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BATON = os.path.join(ROOT, "baton.py")
SHA = "9c6048aff35dc2609cc91a10948b31008952b05c"


class BatonCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = dict(os.environ, BATON_HOME=os.path.join(self.tmp, "ledger"),
                        BATON_KEYS=os.path.join(self.tmp, "keys"))
        for k in ("BATON_GUARD_CMD", "BATON_GUARD_URL", "BATON_GUARD_KEY", "BATON_REQUIRE_SIG"):
            self.env.pop(k, None)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_b(self, *args, ok=True, stdin=None):
        r = subprocess.run([sys.executable, BATON] + list(args), env=self.env, input=stdin,
                           capture_output=True, text=True)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        return r

    def post(self, *args, ok=True):
        return self.run_b("post", "--no-guard", *args, ok=ok)

    def ledger(self):
        with open(os.path.join(self.env["BATON_HOME"], "ledger.jsonl")) as f:
            return [json.loads(x) for x in f if x.strip()]

    def write_ledger(self, entries):
        with open(os.path.join(self.env["BATON_HOME"], "ledger.jsonl"), "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")


class Obligations(BatonCase):
    def test_go_without_scope_is_refused(self):
        r = self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA,
                      "--pipeline", "1", ok=False)
        self.assertEqual(r.returncode, 2)
        self.assertIn("must state scope", r.stderr)

    def test_go_needs_full_sha_and_pipeline(self):
        r = self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA[:7],
                      "--pipeline", "1", "--checked", "x", "--not-checked", "y", ok=False)
        self.assertIn("full 40-hex", r.stderr)
        r = self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA,
                      "--checked", "x", "--not-checked", "y", ok=False)
        self.assertIn("--pipeline", r.stderr)

    def test_finding_needs_scope_and_evidence(self):
        r = self.post("--as", "assay", "--to", "forge", "--act", "FINDING", "--text", "bug",
                      "--checked", "x", "--not-checked", "y", ok=False)
        self.assertIn("--ticket or --result", r.stderr)

    def test_replies_need_an_existing_target(self):
        r = self.post("--as", "forge", "--to", "assay", "--act", "DONE", "--text", "x", ok=False)
        self.assertIn("--re", r.stderr)
        r = self.post("--as", "forge", "--to", "assay", "--act", "DONE", "--re", "9",
                      "--text", "x", ok=False)
        self.assertIn("does not exist", r.stderr)

    def test_valid_go_is_accepted(self):
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA,
                  "--pipeline", "42", "--checked", "CI green", "--not-checked", "prod")
        e = self.ledger()[0]
        self.assertEqual(e["ref"], {"sha": SHA, "pipeline": "42"})
        self.assertEqual(e["evidence"]["not_checked"], ["prod"])

    def test_go_with_ci_exception(self):
        # #6: no CI run, so the GO names where the owner granted the exception, and what replaced CI.
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "owner: local suites OK")
        go = ("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA,
              "--checked", "local suite", "--not-checked", "CI")
        r = self.post(*go, "--exception", "1", ok=False)
        self.assertIn("needs --result", r.stderr)
        r = self.post(*go, "--exception", "#9", "--result", "217/217", ok=False)
        self.assertIn("does not exist", r.stderr)
        r = self.post(*go, "--exception", "1", "--pipeline", "42", "--result", "217/217", ok=False)
        self.assertIn("not both", r.stderr)
        self.post(*go, "--exception", "#1", "--result", f"217/217 on {SHA}, by forge and assay")
        e = self.ledger()[1]
        self.assertEqual(e["ref"], {"sha": SHA, "exception": "#1"})
        self.assertIn("exception=#1", self.run_b("show", "2").stdout)
        # A ticket reference is recorded as given; only #N / N is checked against the ledger.
        self.post(*go, "--exception", "PROJ-12", "--result", "217/217")

    def test_go_with_neither_pipeline_nor_exception_is_refused(self):
        for act, extra in (("GO", ("--checked", "x", "--not-checked", "y")), ("NOGO", ("--text", "no"))):
            r = self.post("--as", "assay", "--to", "forge", "--act", act, "--sha", SHA, *extra,
                          ok=False)
            self.assertIn("--pipeline", r.stderr)
            self.assertIn("--exception", r.stderr)

    def test_blank_pipeline_or_exception_counts_as_missing(self):
        for flag in ("--pipeline", "--exception"):
            r = self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA, flag, " ",
                          "--result", "x", "--checked", "x", "--not-checked", "y", ok=False)
            self.assertIn("needs --pipeline", r.stderr)

    def test_nogo_with_exception(self):
        r = self.post("--as", "assay", "--to", "forge", "--act", "NOGO", "--sha", SHA, "--text", "2 fail",
                      "--exception", "PROJ-12", ok=False)
        self.assertIn("needs --result", r.stderr)
        self.post("--as", "assay", "--to", "forge", "--act", "NOGO", "--sha", SHA, "--text", "2 fail",
                  "--exception", "PROJ-12", "--result", "215/217")


    def test_test_command_is_recorded_and_shown(self):
        # #7: how it was tested, recorded verbatim (the tool does not run it).
        cmd = "python3 -m unittest discover -s tests"
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA, "--pipeline", "42",
                  "--checked", "x", "--not-checked", "y", "--test-cmd", cmd, "--test-cmd", "ruff check .")
        self.post("--as", "assay", "--to", "forge", "--act", "FINDING", "--text", "bug", "--ticket", "T-1",
                  "--checked", "x", "--not-checked", "y", "--test-cmd", cmd)
        go, finding = self.ledger()
        self.assertEqual(go["evidence"]["test_cmd"], [cmd, "ruff check ."])
        self.assertEqual(finding["evidence"]["test_cmd"], [cmd])
        self.assertIn(f"test: {cmd}", self.run_b("show", "1").stdout)
        self.run_b("verify")

    def test_test_command_is_optional(self):
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA, "--pipeline", "42",
                  "--checked", "x", "--not-checked", "y", "--test-cmd", "  ")
        self.assertNotIn("test_cmd", self.ledger()[0]["evidence"])


    def test_artifact_digest_on_go(self):
        # #8 (lobsternigel): the digest of the built file a GO approves.
        d = "sha256:" + "ab" * 32
        go = ("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA, "--pipeline", "42",
              "--checked", "x", "--not-checked", "y")
        self.post(*go, "--digest", d)
        self.assertEqual(self.ledger()[0]["ref"]["digest"], d)
        self.assertIn("digest=sha256:abababababab", self.run_b("show", "1").stdout)
        for bad in ("ab" * 32, "sha256:" + "AB" * 32, "sha256:" + "ab" * 31, "md5:" + "ab" * 16):
            r = self.post(*go, "--digest", bad, ok=False)
            self.assertIn("--digest must be", r.stderr)
        self.post(*go, "--digest", "sha512:" + "cd" * 64)


    # --- #14: a GO must not approve its own author's work (merktop, odin-slidphi) ---
    GO_SCOPE = ("--checked", "x", "--not-checked", "y")

    def test_go_answering_your_own_request_is_refused(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "GO?", "--sha", SHA)
        r = self.post("--as", "forge", "--to", "assay", "--act", "GO", "--re", "1", "--sha", SHA,
                      "--pipeline", "1", *self.GO_SCOPE, ok=False)
        self.assertIn("someone other than the author", r.stderr)
        self.assertIn("#1, a REQUEST by forge", r.stderr)
        self.assertEqual(len(self.ledger()), 1)  # a refused post writes nothing
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--re", "1", "--sha", SHA,
                  "--pipeline", "1", *self.GO_SCOPE)

    def test_go_on_a_sha_you_reported_done_is_refused_without_re(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "build it")
        self.post("--as", "assay", "--to", "forge", "--act", "DONE", "--re", "1", "--text", "built",
                  "--sha", SHA)
        r = self.post("--as", "assay", "--to", "forge", "--act", "GO", "--sha", SHA,
                      "--pipeline", "1", *self.GO_SCOPE, ok=False)
        self.assertIn("#2, a DONE by assay, names the same SHA", r.stderr)

    def test_a_verifier_may_reverse_its_own_nogo_and_cite_its_own_notes(self):
        # Both shapes are on our own ledger (#18, #22) and must stay allowed.
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "GO?", "--sha", SHA)
        self.post("--as", "assay", "--to", "forge", "--act", "INFORM", "--text", "review notes",
                  "--sha", SHA)
        self.post("--as", "assay", "--to", "forge", "--act", "NOGO", "--re", "1", "--sha", SHA,
                  "--pipeline", "1", "--text", "tests red")
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--re", "3", "--sha", SHA,
                  "--pipeline", "2", *self.GO_SCOPE)

    def test_only_request_and_done_mark_work(self):
        # A head announced only as an INFORM is not covered (SPEC says so; post it as a REQUEST).
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "new head",
                  "--sha", SHA)
        self.post("--as", "forge", "--to", "assay", "--act", "GO", "--re", "1", "--sha", SHA,
                  "--pipeline", "1", *self.GO_SCOPE)
        # The same head posted for review as a REQUEST is covered, with or without --re.
        other = "a" * 40
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "GO?",
                  "--sha", other)
        r = self.post("--as", "forge", "--to", "assay", "--act", "GO", "--sha", other,
                      "--pipeline", "1", *self.GO_SCOPE, ok=False)
        self.assertIn("#3, a REQUEST by forge, names the same SHA", r.stderr)

    def test_a_go_answering_your_own_inform_is_allowed(self):
        self.post("--as", "assay", "--to", "forge", "--act", "INFORM", "--text", "review notes")
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--re", "1", "--sha", SHA,
                  "--pipeline", "1", *self.GO_SCOPE)

    def test_verify_lists_self_approved_gos_already_on_a_ledger(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "GO?", "--sha", SHA)
        self.post("--as", "assay", "--to", "forge", "--act", "GO", "--re", "1", "--sha", SHA,
                  "--pipeline", "1", *self.GO_SCOPE)
        self.assertIn("self-approved GOs: none", self.run_b("verify").stdout)
        entries = self.ledger()
        entries[1]["from"] = "forge"  # as an older tool, or another writer, could have left it
        # Re-hash so the chain stays intact: only the self-approval listing is under test.
        sys.path.insert(0, ROOT)
        import baton as b
        prev = b.GENESIS
        for e in entries:
            e.pop("sig", None)
            e["prev"] = prev
            e["hash"] = b.entry_hash(e)
            prev = e["hash"]
        self.write_ledger(entries)
        out = self.run_b("verify").stdout
        self.assertIn("chain: intact", out)
        self.assertIn("self-approved GOs: [2]", out)


class Flow(BatonCase):
    def test_cursor_reads_only_new_and_only_addressed(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "one")
        self.post("--as", "forge", "--to", "hallmark", "--act", "INFORM", "--text", "not yours")
        self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", "everyone")
        out = self.run_b("read", "--as", "assay").stdout
        self.assertIn("one", out)
        self.assertIn("everyone", out)
        self.assertNotIn("not yours", out)
        self.assertIn("nothing new", self.run_b("read", "--as", "assay").stdout)

    def test_open_requests_close_on_done(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "please")
        self.assertIn("please", self.run_b("open", "--as", "assay").stdout)
        self.post("--as", "assay", "--to", "forge", "--act", "DONE", "--re", "1", "--text", "ok")
        self.assertIn("no open requests", self.run_b("open", "--as", "assay").stdout)

    def test_correction_marks_the_original(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "n=14")
        self.post("--as", "forge", "--to", "assay", "--act", "CORRECT", "--re", "1",
                  "--text", "n=29")
        self.assertIn("[CORRECTED by #2]", self.run_b("show", "1").stdout)

    def test_thread_collects_replies(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "root")
        self.post("--as", "assay", "--to", "forge", "--act", "ACK", "--re", "1")
        self.post("--as", "assay", "--to", "forge", "--act", "DONE", "--re", "1", "--text", "x")
        self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", "unrelated")
        out = self.run_b("thread", "3").stdout
        self.assertEqual(out.count("\n#"), 2)  # #1, #2, #3: first line has no leading \n
        self.assertNotIn("unrelated", out)


class Brief(BatonCase):
    """read --brief: one line per entry, but never at the cost of a caveat or a correction (#20)."""

    def brief(self):
        return self.run_b("read", "--as", "assay", "--brief").stdout

    def test_plain_entries_collapse_to_their_header(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--subject", "deploy",
                  "--text", "long body that brief mode leaves for show")
        out = self.brief()
        self.assertIn("INFORM", out)
        self.assertIn("«deploy»", out)
        self.assertNotIn("long body", out)
        self.assertIn("long body", self.run_b("show", "1").stdout)

    def test_default_read_is_unchanged(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "full body")
        self.assertIn("full body", self.run_b("read", "--as", "assay").stdout)

    def test_go_prints_in_full_with_its_scope(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "warm-up")
        self.post("--as", "hallmark", "--to", "assay", "--act", "GO", "--sha", SHA,
                  "--pipeline", "1", "--checked", "ran suite", "--not-checked", "prod",
                  "--text", "go body")
        out = self.brief()
        self.assertIn("go body", out)
        self.assertIn("NOT checked: prod", out)
        self.assertNotIn("warm-up", out)

    def test_nogo_prints_in_full(self):
        self.post("--as", "hallmark", "--to", "assay", "--act", "NOGO", "--sha", SHA, "--pipeline", "1",
                  "--checked", "x", "--not-checked", "y", "--text", "nogo body")
        self.assertIn("nogo body", self.brief())

    def test_finding_prints_in_full(self):
        self.post("--as", "forge", "--to", "assay", "--act", "FINDING", "--ticket", "T-1",
                  "--checked", "x", "--not-checked", "y", "--text", "finding body")
        self.assertIn("finding body", self.brief())

    def test_correction_prints_in_full_and_marks_the_original(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "n=14")
        self.post("--as", "forge", "--to", "assay", "--act", "CORRECT", "--re", "1",
                  "--text", "n=29")
        out = self.brief()
        self.assertIn("[CORRECTED by #2]", out.splitlines()[0])
        self.assertIn("n=29", out)
        self.assertNotIn("n=14", out)

    def test_not_checked_is_flagged_on_a_collapsed_line(self):
        self.post("--as", "forge", "--to", "assay", "--act", "REQUEST", "--text", "review",
                  "--checked", "unit", "--not-checked", "e2e")
        line = self.brief().strip()
        self.assertEqual(len(line.splitlines()), 1)
        self.assertIn("[has not-checked]", line)

    def test_guard_flag_survives_on_a_collapsed_line(self):
        script = os.path.join(self.tmp, "guard.py")
        with open(script, "w") as f:
            f.write("import json\nprint(json.dumps({'action':'blocked','rails':['demo']}))\n")
        self.env["BATON_GUARD_CMD"] = f"{sys.executable} {script}"
        self.run_b("post", "--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "hi")
        self.assertIn("[guard: blocked]", self.brief())

    def test_brief_advances_the_cursor_like_read(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "one")
        self.brief()
        self.assertIn("nothing new", self.brief())


class Integrity(BatonCase):
    def test_concurrent_writers_keep_a_gapless_chain(self):
        def one(i):
            return self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", f"p{i}")
        with ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(one, range(40)))
        self.assertEqual([e["seq"] for e in self.ledger()], list(range(1, 41)))
        self.assertIn("chain: intact (40 entries)", self.run_b("verify").stdout)

    def test_edit_is_detected(self):
        self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", "original")
        self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", "second")
        entries = self.ledger()
        entries[0]["text"] = "edited"
        self.write_ledger(entries)
        r = self.run_b("verify", ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("hash mismatch at seq 1", r.stdout)

    def test_deletion_is_detected(self):
        for t in ("a", "b", "c"):
            self.post("--as", "forge", "--to", "*", "--act", "INFORM", "--text", t)
        entries = self.ledger()
        self.write_ledger([entries[0], entries[2]])
        self.assertIn("BROKEN", self.run_b("verify", ok=False).stdout)


@unittest.skipUnless(shutil.which("ssh-keygen"), "needs OpenSSH ssh-keygen")
class Signatures(BatonCase):
    def test_signed_entries_verify(self):
        self.run_b("keygen", "--as", "forge")
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "signed")
        self.assertIn("BEGIN SSH SIGNATURE", self.ledger()[0]["sig"])
        out = self.run_b("verify", "--strict").stdout
        self.assertIn("1 good, 0 BAD", out)

    def test_keygen_refuses_to_overwrite(self):
        self.run_b("keygen", "--as", "forge")
        self.assertIn("refusing", self.run_b("keygen", "--as", "forge", ok=False).stderr)

    def test_impersonation_fails(self):
        """An entry claiming to be from assay but signed with forge's key is BAD."""
        self.run_b("keygen", "--as", "forge")
        self.run_b("keygen", "--as", "assay")
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "real")
        e = self.ledger()[0]
        e["from"] = "assay"
        sys.path.insert(0, ROOT)
        import baton
        e["hash"] = baton.entry_hash(e)  # a forger can recompute the hash, not the signature
        self.write_ledger([e])
        r = self.run_b("verify", ok=False)
        self.assertIn("1 BAD", r.stdout)

    def test_unsigned_fails_only_in_strict_mode(self):
        self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "plain")
        self.assertIn("1 unsigned", self.run_b("verify").stdout)
        self.assertEqual(self.run_b("verify", "--strict", ok=False).returncode, 1)

    def test_require_sig_refuses_keyless_posts(self):
        self.env["BATON_REQUIRE_SIG"] = "1"
        r = self.post("--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "x", ok=False)
        self.assertIn("no signing key", r.stderr)


class Guard(BatonCase):
    def test_guard_verdict_is_recorded_and_never_blocks(self):
        script = os.path.join(self.tmp, "guard.py")
        with open(script, "w") as f:
            f.write("import sys,json\nt=sys.stdin.read()\n"
                    "print(json.dumps({'action':'blocked' if 'now' in t else 'allowed',"
                    "'rails':['demo']}))\n")
        self.env["BATON_GUARD_CMD"] = f"{sys.executable} {script}"
        self.run_b("post", "--as", "forge", "--to", "assay", "--act", "INFORM",
                   "--text", "the deploy is starting now")
        e = self.ledger()[0]
        self.assertEqual(e["guard"]["action"], "blocked")
        self.assertIn("the deploy is starting now", self.run_b("read", "--as", "assay").stdout)
        self.assertIn("guard would have blocked or modified: [1]", self.run_b("verify").stdout)

    def test_could_not_check_is_not_flagged_as_a_block(self):
        script = os.path.join(self.tmp, "guard.py")
        with open(script, "w") as f:
            f.write("import json\nprint(json.dumps({'action':'blocked','rails':['x'],"
                    "'unavailable':'timed_out_blocked'}))\n")
        self.env["BATON_GUARD_CMD"] = f"{sys.executable} {script}"
        self.run_b("post", "--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "hi")
        self.assertEqual(self.ledger()[0]["guard"]["unavailable"], "timed_out_blocked")
        out = self.run_b("verify").stdout
        self.assertIn("would have blocked or modified: none; could not check: [1]", out)
        self.assertIn("could not check (timed_out_blocked)", self.run_b("show", "1").stdout)

    def test_unreachable_guard_is_recorded_not_fatal(self):
        self.env["BATON_GUARD_URL"] = "http://127.0.0.1:9"
        self.env["BATON_GUARD_KEY"] = "x"
        self.run_b("post", "--as", "forge", "--to", "assay", "--act", "INFORM", "--text", "hi")
        self.assertEqual(self.ledger()[0]["guard"]["action"], "unchecked")


if __name__ == "__main__":
    unittest.main()
