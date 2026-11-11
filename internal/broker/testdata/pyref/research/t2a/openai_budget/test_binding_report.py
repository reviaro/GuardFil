"""Offline boundary tests for LedgerBinding / verify_binding / read_recorded_report.

Observes the ACTUAL syscall boundary (os/fcntl calls) on disposable private state:
no network, credentials, live ledger, broker, listener or paid call.
"""

import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import traceback
import dataclasses
import unittest
from unittest.mock import patch

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from research.t2a.openai_budget import (
    BudgetLedger, LedgerBinding, LedgerBindingError, LedgerReportUnavailableError,
    RecordedLedgerReport, read_recorded_report,
)
from research.t2a.openai_budget.exceptions import LedgerCorruptError, LedgerHaltedError
from research.t2a.openai_budget.test_ledger import _make_receipt


class Trace:
    """Records every filesystem-affecting syscall issued through os/fcntl while active."""

    def __init__(self, hook=None):
        self.events = []
        self.hook = hook  # hook(event_tuple) after the real call
        self._p = []

    def __enter__(self):
        t = self
        real = {n: getattr(os, n) for n in (
            "open", "read", "write", "fsync", "close", "replace", "rename", "unlink", "mkdir",
            "ftruncate", "stat", "fstat", "chmod", "link", "symlink", "listdir", "scandir")}
        real_flock = fcntl.flock
        self.real = real

        def wrap(name):
            def f(*a, **kw):
                ev = (name, a[0] if a else None) + ((kw.get("dir_fd") is not None,) if kw else ())
                if name == "open":
                    ev = ("open", a[0], a[1], kw.get("dir_fd"))
                t.events.append(ev)
                res = real[name](*a, **kw)
                if t.hook:
                    t.hook(ev, res)
                return res
            return f

        for n in real:
            p = patch(f"os.{n}", side_effect=wrap(n))
            p.start()
            self._p.append(p)

        def flock(fd, op):
            t.events.append(("flock", fd, op))
            r = real_flock(fd, op)
            if t.hook:
                t.hook(("flock", fd, op), r)
            return r

        p = patch("fcntl.flock", side_effect=flock)
        p.start()
        self._p.append(p)
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()
        return False

    def names(self, op):
        return [e for e in self.events if e[0] == op]


def read_only_flags(flags):
    return not (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="guardfil-binding-test-")
        self.root = os.path.join(self.tmp.name, "exp")
        os.mkdir(self.root, 0o700)
        self.ledger_dir = os.path.join(self.root, "ledger")
        self.h = BudgetLedger.initialize(self.ledger_dir)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.binding = self.binding_of(self.ledger_dir)
        self._handles = [self.h]

    def tearDown(self):
        for h in self._handles:
            h.close()
        try:
            os.close(self.root_fd)
        except OSError:
            pass
        self.tmp.cleanup()

    def binding_of(self, ledger_dir, experiment_id=None):
        """Independent capture via plain stat calls (not via the implementation)."""
        d = os.stat(ledger_dir)
        l = os.stat(os.path.join(ledger_dir, "ledger.lock"))
        return LedgerBinding(experiment_id or "guardfil-t2a-m1-openai-luna", d.st_dev, d.st_ino, l.st_dev, l.st_ino)

    def raw(self, name="ledger.json"):
        with open(os.path.join(self.ledger_dir, name), "rb") as f:
            return f.read()

    def snapshot(self):
        out = {}
        for n in sorted(os.listdir(self.ledger_dir)):
            st = os.stat(os.path.join(self.ledger_dir, n))
            with open(os.path.join(self.ledger_dir, n), "rb") as f:
                out[n] = (st.st_ino, st.st_mtime_ns, st.st_mode, hashlib.sha256(f.read()).hexdigest())
        return out

    def assertRootAlive(self):
        st = os.fstat(self.root_fd)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertEqual((st.st_dev, st.st_ino), (os.stat(self.root).st_dev, os.stat(self.root).st_ino))

    def lock_free(self, op=fcntl.LOCK_EX):
        fd = os.open(os.path.join(self.ledger_dir, "ledger.lock"), os.O_RDWR)
        try:
            fcntl.flock(fd, op | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return True
        except BlockingIOError:
            return False
        finally:
            os.close(fd)

    def holding(self, op):
        fd = os.open(os.path.join(self.ledger_dir, "ledger.lock"), os.O_RDWR)
        fcntl.flock(fd, op)
        self.addCleanup(os.close, fd)
        return fd

    def settle_one(self, h, rid="resp_1"):
        p = h.reserve("req_" + rid, "sha256:" + rid)
        h.settle(p, _make_receipt(p, response_id=rid, input_tokens=1000, output_tokens=500))
        return p


class TestLedgerBindingModel(Base):
    def test_fields_exact_immutable_and_authority_free(self):
        self.assertEqual([f.name for f in dataclasses.fields(LedgerBinding)],
                         ["experiment_id", "directory_device", "directory_inode",
                          "transaction_lock_device", "transaction_lock_inode"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.binding.directory_inode = 5
        public = {n for n in dir(self.binding) if not n.startswith("_")}
        self.assertFalse(public & {"permit", "fd", "nonce", "can_reserve", "reserve", "settle"})

    def test_bounds_and_strict_types(self):
        ok = dict(experiment_id="exp", directory_device=0, directory_inode=1,
                  transaction_lock_device=2 ** 64 - 1, transaction_lock_inode=2 ** 64 - 1)
        LedgerBinding(**ok)  # healthy control (device 0 and maxima allowed)
        for k, v in (("directory_inode", 0), ("transaction_lock_inode", 0), ("directory_device", -1),
                     ("directory_device", 2 ** 64), ("directory_inode", True), ("directory_device", 1.0),
                     ("transaction_lock_device", "1"), ("experiment_id", ""), ("experiment_id", "a b"),
                     ("experiment_id", "x" * 129), ("experiment_id", 7)):
            with self.subTest(k=k, v=v), self.assertRaises(LedgerBindingError) as c:
                LedgerBinding(**dict(ok, **{k: v}))
            self.assertEqual(str(c.exception), "BINDING_INVALID")


class TestVerifyBinding(Base):
    def assertBindingFails(self, code, h=None, binding=None, poisoned=True, root_fd=None):
        h = h or self.h
        with self.assertRaises(LedgerBindingError) as c:
            h.verify_binding(self.root_fd if root_fd is None else root_fd, binding or self.binding)
        e = c.exception
        self.assertEqual(str(e), code)
        self.assertEqual(e.code, code)
        self.assertIsNone(e.__cause__)
        self.assertTrue(e.__suppress_context__)
        self.assertEqual(h.is_handle_disabled, poisoned)
        self.assertRootAlive()
        return e

    def test_matched_identity_succeeds_without_state_reads_or_writes(self):
        p = self.h.reserve("req_pend", "sha256:p")  # pending reservation + held permit lease
        before = self.snapshot()
        with Trace() as t:
            got = self.h.verify_binding(self.root_fd, self.binding)
        self.assertEqual(got, self.binding)
        self.assertEqual(self.snapshot(), before)
        # allowlisted syscalls only: no state/guard/evidence/lease opens, no writes
        opened = [e[1] for e in t.names("open")]
        self.assertTrue(set(opened) <= {"ledger", "ledger.lock", self.ledger_dir}, opened)
        self.assertTrue(all(read_only_flags(e[2]) for e in t.names("open")))
        for banned in ("write", "fsync", "replace", "rename", "unlink", "mkdir", "ftruncate", "chmod",
                       "link", "symlink", "read", "listdir", "scandir"):
            self.assertEqual(t.names(banned), [], banned)
        flocks = [e[2] for e in t.names("flock")]
        self.assertEqual(flocks, [fcntl.LOCK_EX | fcntl.LOCK_NB, fcntl.LOCK_UN])
        # handle, pending reservation and permit lease untouched; lock released
        self.assertFalse(self.h.is_handle_disabled)
        self.assertTrue(self.lock_free())
        self.assertIsNotNone(self.h._held_lease_fd)
        self.h.settle(p, _make_receipt(p))

    def test_each_closed_descriptor_is_closed_exactly_once_and_root_never(self):
        closes = []
        with Trace() as t:
            self.h.verify_binding(self.root_fd, self.binding)
        closes = [e[1] for e in t.names("close")]
        self.assertEqual(len(closes), len(set(closes)))
        self.assertNotIn(self.root_fd, closes)
        opened_fds = []
        self.assertEqual(len(closes), 3)  # ledger dir, lock, configured-path dir

    def test_wrong_expected_identity_or_experiment_poisons_and_releases_lease(self):
        b = self.binding
        variants = {
            "experiment": dataclasses.replace(b, experiment_id="other-exp"),
            "dir_inode": dataclasses.replace(b, directory_inode=b.directory_inode + 1),
            "dir_device": dataclasses.replace(b, directory_device=b.directory_device + 1),
            "lock_inode": dataclasses.replace(b, transaction_lock_inode=b.transaction_lock_inode + 1),
            "lock_device": dataclasses.replace(b, transaction_lock_device=b.transaction_lock_device + 1),
        }
        for label, bad in variants.items():
            with self.subTest(label):
                self.tearDown(); self.setUp()
                self.h.reserve("req_pend", "sha256:p")
                self.assertIsNotNone(self.h._held_lease_fd)
                self.assertBindingFails("BINDING_INVALID", binding=bad)
                self.assertIsNone(self.h._held_lease_fd, "permit lease released")
                self.assertTrue(self.lock_free())

    def test_replaced_directory_or_lock_with_original_descriptors_open_fails(self):
        # (a) root's `ledger` entry replaced by a different ledger while handle's descriptors stay open
        other = os.path.join(self.tmp.name, "other")
        BudgetLedger.initialize(other).close()
        os.rename(self.ledger_dir, os.path.join(self.tmp.name, "moved"))
        os.rename(other, self.ledger_dir)
        self.assertBindingFails("BINDING_INVALID")
        # (b) lock file replaced in place
        self.tearDown(); self.setUp()
        lp = os.path.join(self.ledger_dir, "ledger.lock")
        with open(lp, "rb") as fh:
            shutil_copy = fh.read()
        os.rename(lp, lp + ".old")
        with open(lp, "wb") as f:
            f.write(shutil_copy)
        os.chmod(lp, 0o600)
        self.assertBindingFails("BINDING_INVALID")

    def test_configured_path_mismatch_fails(self):
        other = os.path.join(self.tmp.name, "other")
        BudgetLedger.initialize(other).close()
        self.h._ledger_dir = other  # handle's configured path now names a different directory
        self.assertBindingFails("BINDING_INVALID")

    def test_symlink_fifo_nonregular_and_modes_fail(self):
        # symlinked root entry
        os.rename(self.ledger_dir, os.path.join(self.tmp.name, "real"))
        os.symlink(os.path.join(self.tmp.name, "real"), self.ledger_dir)
        self.assertBindingFails("BINDING_INVALID")
        for label in ("fifo_lock", "dir_lock", "lock_mode", "dir_mode", "lock_symlink", "lock_hardlink"):
            with self.subTest(label):
                self.tearDown(); self.setUp()
                lp = os.path.join(self.ledger_dir, "ledger.lock")
                if label == "fifo_lock":
                    os.rename(lp, lp + ".x"); os.mkfifo(lp, 0o600)
                elif label == "dir_lock":
                    os.rename(lp, lp + ".x"); os.mkdir(lp, 0o700)
                elif label == "lock_mode":
                    os.chmod(lp, 0o644)
                elif label == "dir_mode":
                    os.chmod(self.ledger_dir, 0o750)
                elif label == "lock_symlink":
                    os.rename(lp, lp + ".x"); os.symlink(lp + ".x", lp)
                else:
                    os.link(lp, lp + ".hard")
                t0 = time.monotonic()
                self.assertBindingFails("BINDING_INVALID" if label != "dir_mode" else "BINDING_INVALID")
                self.assertLess(time.monotonic() - t0, 2.0, "FIFO must not block")
                if label == "dir_mode":
                    os.chmod(self.ledger_dir, 0o700)

    def test_root_must_be_private_directory(self):
        os.chmod(self.root, 0o750)
        try:
            self.assertBindingFails("BINDING_INVALID")
        finally:
            os.chmod(self.root, 0o700)
        f = os.open(os.path.join(self.root, "ledger", "ledger.lock"), os.O_RDONLY)
        try:
            self.tearDown(); self.setUp()
            self.assertBindingFails("BINDING_INVALID", root_fd=f)
        finally:
            os.close(f)

    def test_entry_replacement_after_lock_is_caught_by_final_checks(self):
        replaced = []

        def hook(ev, res):
            if ev[0] == "flock" and ev[2] == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not replaced:
                replaced.append(1)
                os.rename(self.ledger_dir, self.ledger_dir + ".gone")
                os.mkdir(self.ledger_dir, 0o700)

        with Trace(hook=hook):
            self.assertBindingFails("BINDING_INVALID")
        self.assertTrue(replaced)
        # same race on the lock entry only
        self.tearDown(); self.setUp()
        replaced.clear()

        def hook2(ev, res):
            if ev[0] == "flock" and ev[2] == (fcntl.LOCK_EX | fcntl.LOCK_NB) and not replaced:
                replaced.append(1)
                lp = os.path.join(self.ledger_dir, "ledger.lock")
                os.rename(lp, lp + ".gone")
                open(lp, "wb").close(); os.chmod(lp, 0o600)

        with Trace(hook=hook2):
            self.assertBindingFails("BINDING_INVALID")

    def test_held_transaction_lock_gives_bounded_refusal(self):
        self.holding(fcntl.LOCK_EX)
        p = None
        t0 = time.monotonic()
        self.assertBindingFails("BINDING_BUSY")
        self.assertLess(time.monotonic() - t0, 2.0)
        # shared holder also conflicts with the exclusive probe
        self.tearDown(); self.setUp()
        self.holding(fcntl.LOCK_SH)
        self.assertBindingFails("BINDING_BUSY")

    def test_disabled_and_closed_handles_cannot_pass(self):
        before = self.snapshot()
        with Trace() as t:
            self.h.close()
            self.assertBindingFails("BINDING_DISABLED", poisoned=True)
        self.assertEqual(t.names("flock"), [])
        self.assertEqual(self.snapshot(), before)
        # poisoned by a failed operation
        self.tearDown(); self.setUp()
        p = self.h.reserve("r", "sha256:r")
        with self.assertRaises(Exception):
            self.h.record_failure(p, "NOT_A_CODE")
        self.assertBindingFails("BINDING_DISABLED")

    def test_unbound_direct_constructor_and_wrong_established_experiment(self):
        direct = BudgetLedger(self.ledger_dir)  # no established directory/lock identities
        self._handles.append(direct)
        self.assertBindingFails("BINDING_INVALID", h=direct)
        self.assertIsNone(direct._dir_dev_ino, "missing identity is never initialized by verify_binding")
        wrong = BudgetLedger(self.ledger_dir, "other-exp", dir_dev_ino=(self.binding.directory_device, self.binding.directory_inode),
                             lock_dev_ino=(self.binding.transaction_lock_device, self.binding.transaction_lock_inode))
        self._handles.append(wrong)
        self.assertBindingFails("BINDING_INVALID", h=wrong)

    def test_identity_success_does_not_prove_health_or_accounting(self):
        p = self.settle_one(self.h)
        os.unlink(os.path.join(self.ledger_dir, f"confirmation_{p.permit_id}.json"))  # lost evidence
        self.assertEqual(self.h.verify_binding(self.root_fd, self.binding), self.binding)
        with self.assertRaises(LedgerHaltedError):
            self.h.reserve("next", "sha256:n")  # the guarded operation, not binding, catches it
        # corrupt state with unchanged identities
        self.tearDown(); self.setUp()
        with open(os.path.join(self.ledger_dir, "ledger.json"), "w") as f:
            f.write("{corrupt")
        self.assertEqual(self.h.verify_binding(self.root_fd, self.binding), self.binding)
        with self.assertRaises(LedgerCorruptError):
            self.h.reserve("next", "sha256:n")
        # state experiment id changed: binding cannot see it
        self.tearDown(); self.setUp()
        st = json.loads(self.raw())
        st["experiment_id"] = "swapped-exp"
        with open(os.path.join(self.ledger_dir, "ledger.json"), "w") as f:
            json.dump(st, f)
        self.assertEqual(self.h.verify_binding(self.root_fd, self.binding), self.binding)
        with self.assertRaises(LedgerCorruptError):
            self.h.reserve("next", "sha256:n")

    def test_argument_errors_do_not_touch_handle(self):
        for bad_fd, bad_b in ((True, self.binding), (-1, self.binding), ("3", self.binding), (self.root_fd, object()),
                              (self.root_fd, None)):
            with self.subTest(fd=bad_fd), self.assertRaises(LedgerBindingError) as c:
                self.h.verify_binding(bad_fd, bad_b)
            self.assertEqual(str(c.exception), "BINDING_INVALID")
            self.assertFalse(self.h.is_handle_disabled)

    # ---- mutex busy (real threads) -----------------------------------------
    def test_busy_handle_mutex_refuses_bounded_without_poison_or_release(self):
        entered, release = threading.Event(), threading.Event()
        real = BudgetLedger._guarded_state
        out = {}

        def slow(self_, dir_fd):
            st = real(self_, dir_fd)
            entered.set()
            self.assertTrue(release.wait(10))
            return st

        def worker():
            out["permit"] = self.h.reserve("req_inflight", "sha256:inf")

        with patch.object(BudgetLedger, "_guarded_state", slow):
            t = threading.Thread(target=worker)
            t.start()
            self.assertTrue(entered.wait(10))
            t0 = time.monotonic()
            with Trace() as tr:
                with self.assertRaises(LedgerBindingError) as c:
                    self.h.verify_binding(self.root_fd, self.binding)
            self.assertLess(time.monotonic() - t0, 2.0)
            self.assertEqual(tr.events, [], "busy refusal performs no syscalls at all")
            self.assertEqual(str(c.exception), "BINDING_BUSY")
            self.assertFalse(self.h.is_handle_disabled)
            self.assertIsNone(self.h._held_lease_fd, "operation owns the lease only after its own acquire")
            release.set()
            t.join(10)
        self.assertIn("permit", out)  # the in-flight operation completed: not cancelled, not refunded
        self.assertFalse(self.h.is_handle_disabled)
        self.assertIsNotNone(self.h._held_lease_fd)
        self.assertEqual(self.h.get_status().pending_request_id, "req_inflight")
        # healthy control: once idle the identical call succeeds
        self.assertEqual(self.h.verify_binding(self.root_fd, self.binding), self.binding)

    def test_close_racing_busy_binding_never_releases_the_other_operations_handle(self):
        entered, release = threading.Event(), threading.Event()
        real = BudgetLedger._guarded_state

        def slow(self_, dir_fd):
            st = real(self_, dir_fd)
            entered.set()
            release.wait(10)
            return st

        res = {}
        with patch.object(BudgetLedger, "_guarded_state", slow):
            t = threading.Thread(target=lambda: res.setdefault("p", self.h.reserve("r", "sha256:r")))
            t.start()
            entered.wait(10)
            with self.assertRaises(LedgerBindingError):
                self.h.verify_binding(self.root_fd, self.binding)
            self.assertFalse(self.h._poisoned)
            release.set(); t.join(10)
        self.assertIn("p", res)

    # ---- read / close / unlock faults --------------------------------------
    def _fault_run(self, mode, nth_target):
        """mode: open|stat|close|unlock|fstat. Returns (exception_code, replacements)."""
        replacements = []
        real_close, real_open = os.close, os.open
        seen = {"n": 0}

        def close_fault(fd):
            seen["n"] += 1
            if mode == "close" and seen["n"] == nth_target:
                real_close(fd)
                replacements.append((fd, real_open(os.devnull, os.O_RDONLY)))
                raise OSError(errno.EIO, "close fault")
            return real_close(fd)

        def open_fault(path, flags, *a, **kw):
            if mode == "open" and path == "ledger.lock":
                raise OSError(errno.EIO, "open fault")
            return real_open(path, flags, *a, **kw)

        real_flock = fcntl.flock

        def flock_fault(fd, op):
            if mode == "unlock" and op == fcntl.LOCK_UN:
                raise OSError(errno.EIO, "unlock fault")
            return real_flock(fd, op)

        patches = [patch("os.close", side_effect=close_fault), patch("os.open", side_effect=open_fault),
                   patch("fcntl.flock", side_effect=flock_fault)]
        for p in patches:
            p.start()
        try:
            with self.assertRaises(LedgerBindingError) as c:
                self.h.verify_binding(self.root_fd, self.binding)
        finally:
            for p in patches:
                p.stop()
        return c.exception, replacements

    def test_io_close_and_unlock_faults_fail_poison_and_never_double_close(self):
        for mode, nth in (("open", 0), ("unlock", 0), ("close", 1), ("close", 2), ("close", 3)):
            with self.subTest(mode=mode, nth=nth):
                self.tearDown(); self.setUp()
                self.h.reserve("req_pend", "sha256:p")
                e, repl = self._fault_run(mode, nth)
                self.assertEqual(str(e), "BINDING_IO_FAILED")
                self.assertTrue(self.h.is_handle_disabled)
                self.assertIsNone(self.h._held_lease_fd)
                for fd, r in repl:
                    self.assertEqual(r, fd, "same descriptor number reused")
                    os.fstat(r)  # replacement survived: not closed twice
                    os.close(r)
                if mode == "close":
                    self.assertEqual(len(repl), 1)
                self.assertTrue(self.lock_free(), "transaction lock released despite the fault")
                self.assertRootAlive()

    def test_failure_leaves_no_state_mutation(self):
        before = self.snapshot()
        self.assertBindingFails("BINDING_INVALID", binding=dataclasses.replace(self.binding, experiment_id="nope"))
        self.assertEqual(self.snapshot(), before)


class TestRecordedReport(Base):
    def assertUnavailable(self, code, binding=None, root_fd=None, check_lock=True):
        with self.assertRaises(LedgerReportUnavailableError) as c:
            read_recorded_report(self.root_fd if root_fd is None else root_fd, binding or self.binding)
        e = c.exception
        self.assertEqual((str(e), e.code), (code, code))
        self.assertIsNone(e.__cause__)
        self.assertTrue(e.__suppress_context__)
        self.assertRootAlive()
        if check_lock:
            self.assertTrue(self.lock_free(), "no lock leaked")
        return e

    def test_report_fields_exact_and_immutable(self):
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual([f.name for f in dataclasses.fields(RecordedLedgerReport)],
                         ["binding", "state_sha256", "recorded_halted", "recorded_halt_reason",
                          "recorded_committed_micros", "recorded_retained_micros", "recorded_pending_micros",
                          "recorded_total_reservations", "recorded_settled_requests", "mode", "reconciliation"])
        self.assertEqual((r.mode, r.reconciliation), ("RECORDED_STATE_ONLY", "NOT_PERFORMED"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.recorded_halted = True
        public = {n for n in dir(r) if not n.startswith("_")}
        self.assertFalse(public & {"can_reserve", "permit", "remaining_available_micros", "ledger"})

    def test_healthy_pending_terminal_and_overlay_reports_use_recorded_fields(self):
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual((r.recorded_halted, r.recorded_halt_reason, r.recorded_committed_micros,
                          r.recorded_retained_micros, r.recorded_pending_micros,
                          r.recorded_total_reservations, r.recorded_settled_requests), (False, None, 0, 0, 0, 0, 0))
        self.assertEqual(r.state_sha256, hashlib.sha256(self.raw()).hexdigest())
        p1 = self.settle_one(self.h)
        self.h.reserve("req_pending", "sha256:pp")
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual((r.recorded_committed_micros, r.recorded_pending_micros, r.recorded_total_reservations,
                          r.recorded_settled_requests, r.recorded_halted), (1500, 1_100_000, 2, 1, False))
        self.assertEqual(r.binding, self.binding)
        # terminal failure
        self.tearDown(); self.setUp()
        p = self.h.reserve("r", "sha256:r")
        self.h.record_failure(p, "REQUEST_TRANSPORT_FAILURE")
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual((r.recorded_halted, r.recorded_halt_reason, r.recorded_retained_micros),
                         (True, "REQUEST_TRANSPORT_FAILURE", 1_100_000))
        # terminal uncertainty overlay recorded by an active handle: reported as recorded
        self.tearDown(); self.setUp()
        p = self.settle_one(self.h)
        os.unlink(os.path.join(self.ledger_dir, f"confirmation_{p.permit_id}.json"))
        with self.assertRaises(LedgerHaltedError):
            self.h.reserve("n", "sha256:n")
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual((r.recorded_halted, r.recorded_halt_reason, r.recorded_retained_micros,
                          r.recorded_committed_micros, r.recorded_settled_requests),
                         (True, "UNRESOLVED_SETTLEMENT_PUBLICATION", 1_100_000, 0, 1))

    def test_unreconciled_evidence_is_not_repaired_or_presented_as_reconciled(self):
        p = self.settle_one(self.h)
        os.unlink(os.path.join(self.ledger_dir, f"confirmation_{p.permit_id}.json"))
        before = self.snapshot()
        r = read_recorded_report(self.root_fd, self.binding)
        self.assertEqual((r.recorded_halted, r.recorded_committed_micros, r.reconciliation), (False, 1500, "NOT_PERFORMED"))
        self.assertEqual(self.snapshot(), before)  # nothing repaired
        # the active, guarded path still detects the lost confirmation
        with self.assertRaises(LedgerHaltedError):
            self.h.reserve("next", "sha256:n")
        # unfinished guard: report still succeeds from recorded state only, writes nothing
        self.tearDown(); self.setUp()
        os.unlink(os.path.join(self.ledger_dir, "inspection_completion.json"))
        before = self.snapshot()
        self.assertFalse(read_recorded_report(self.root_fd, self.binding).recorded_halted)
        self.assertEqual(self.snapshot(), before)

    def test_syscall_allowlist_no_writes_no_active_handle_paths(self):
        p = self.settle_one(self.h)
        pend = self.h.reserve("req_pend", "sha256:pend")  # permit lease held by self.h
        before = self.snapshot()
        listing = sorted(os.listdir(self.ledger_dir))
        boom = AssertionError("active/recovery path used by reporter")
        with patch.object(BudgetLedger, "__init__", side_effect=boom), \
                patch.object(BudgetLedger, "open", side_effect=boom), \
                patch.object(BudgetLedger, "initialize", side_effect=boom), \
                patch.object(BudgetLedger, "get_status", side_effect=boom), \
                patch.object(BudgetLedger, "_guarded_state", side_effect=boom), \
                patch.object(BudgetLedger, "_acquire_lease", side_effect=boom), \
                patch.object(BudgetLedger, "_is_lease_held_static", side_effect=boom), \
                patch.object(BudgetLedger, "_validate_and_recover_records_under_lock", side_effect=boom), \
                Trace() as t:
            r = read_recorded_report(self.root_fd, self.binding)
        self.assertTrue(r.recorded_pending_micros == 1_100_000)
        opens = [(e[1], e[2], e[3]) for e in t.names("open")]
        self.assertEqual([o[0] for o in opens], ["ledger", "ledger.lock", "ledger.json"])
        self.assertTrue(all(read_only_flags(o[1]) and o[1] & os.O_NOFOLLOW and o[1] & os.O_NONBLOCK for o in opens))
        self.assertIs(opens[0][2], self.root_fd)
        for banned in ("write", "fsync", "replace", "rename", "unlink", "mkdir", "ftruncate", "chmod",
                       "link", "symlink", "listdir", "scandir"):
            self.assertEqual(t.names(banned), [], banned)
        self.assertEqual([e[2] for e in t.names("flock")], [fcntl.LOCK_SH | fcntl.LOCK_NB, fcntl.LOCK_UN])
        opened_names = {o[0] for o in opens}
        for forbidden in ("inspection_guard.json", "inspection_completion.json", "lease.lock"):
            self.assertNotIn(forbidden, opened_names)
        closes = [e[1] for e in t.names("close")]
        self.assertEqual(len(closes), len(set(closes)))
        self.assertNotIn(self.root_fd, closes)
        # byte, inode, mtime and directory-entry identity unchanged; permit lease still owned
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(sorted(os.listdir(self.ledger_dir)), listing)
        self.assertFalse(self.h.is_handle_disabled)
        self.h.settle(pend, _make_receipt(pend, response_id="resp_pend"))

    def test_shared_lock_held_through_read_and_not_blocking_other_readers(self):
        observed = {}

        def hook(ev, res):
            if ev[0] == "open" and ev[1] == "ledger.json":
                observed["writer_free"] = self.lock_free(fcntl.LOCK_EX)
                observed["reader_ok"] = self.lock_free(fcntl.LOCK_SH)

        with Trace(hook=hook):
            read_recorded_report(self.root_fd, self.binding)
        self.assertEqual(observed, {"writer_free": False, "reader_ok": True})
        self.assertTrue(self.lock_free())
        # concurrent readers do not exclude each other
        errs = []

        def rd():
            try:
                read_recorded_report(self.root_fd, self.binding)
            except Exception as e:
                errs.append(e)

        ts = [threading.Thread(target=rd) for _ in range(6)]
        [t.start() for t in ts]; [t.join(10) for t in ts]
        self.assertTrue(all(isinstance(e, LedgerReportUnavailableError) and e.code == "REPORT_BUSY" for e in errs))

    def test_busy_transaction_lock_is_bounded_refusal(self):
        self.holding(fcntl.LOCK_EX)
        t0 = time.monotonic()
        self.assertUnavailable("REPORT_BUSY", check_lock=False)
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_binding_mismatch_and_wrong_experiment_invalid(self):
        b = self.binding
        for bad in (dataclasses.replace(b, experiment_id="other"),
                    dataclasses.replace(b, directory_inode=b.directory_inode + 1),
                    dataclasses.replace(b, transaction_lock_inode=b.transaction_lock_inode + 1)):
            self.assertUnavailable("REPORT_INVALID", binding=bad)
        # stored experiment differs from the expected one (identities unchanged)
        st = json.loads(self.raw())
        st["experiment_id"] = "swapped"
        st["journal"][0]["experiment_id"] = "swapped"
        with open(os.path.join(self.ledger_dir, "ledger.json"), "w") as f:
            json.dump(st, f)
        self.assertUnavailable("REPORT_INVALID")

    def test_missing_corrupt_and_oversized_state_are_unavailable(self):
        path = os.path.join(self.ledger_dir, "ledger.json")
        good = self.raw()
        payloads = {
            "garbage": b"{nope", "bad_utf8": b"\xff\xfe{}", "dup_keys": b'{"a":1,"a":2}', "nan": b'{"a":NaN}',
            "deep": json.dumps({"a": {"b": {"c": {"d": {}}}}}).encode(), "list_root": b"[1]",
            "oversize": b" " * 524_289, "empty": b"",
        }
        for label, data in payloads.items():
            with self.subTest(label):
                with open(path, "wb") as f:
                    f.write(data)
                os.chmod(path, 0o600)
                self.assertUnavailable("REPORT_INVALID")
        with open(path, "wb") as f:
            f.write(good)
        os.chmod(path, 0o600)
        read_recorded_report(self.root_fd, self.binding)  # healthy control
        os.unlink(path)
        self.assertUnavailable("REPORT_INVALID")

    def test_depth_bound_allows_legitimate_depth_four(self):
        p = self.settle_one(self.h)
        os.unlink(os.path.join(self.ledger_dir, f"confirmation_{p.permit_id}.json"))
        with self.assertRaises(LedgerHaltedError):
            self.h.reserve("n", "sha256:n")  # produces uncertain_reservation_ids list: depth four
        st = json.loads(self.raw())
        self.assertEqual(st["journal"][-1]["entry_type"], "TERMINAL_UNCERTAINTY")
        read_recorded_report(self.root_fd, self.binding)

    def test_malformed_history_fails_replay(self):
        p = self.settle_one(self.h)
        st = json.loads(self.raw())
        for label, mut in (
            ("halted_without_event", lambda s: s.update(halted=True, halt_reason="TERMINAL_UNCERTAINTY")),
            ("committed_changed", lambda s: s.update(committed_spend_micros=0)),
            ("version_bool", lambda s: s.update(schema_version=True)),
            ("extra_key", lambda s: s.update(extra=1)),
            ("settled_missing_key", lambda s: s["journal"][2].pop("response_id")),
        ):
            with self.subTest(label):
                bad = json.loads(json.dumps(st))
                mut(bad)
                with open(os.path.join(self.ledger_dir, "ledger.json"), "w") as f:
                    json.dump(bad, f)
                self.assertUnavailable("REPORT_INVALID")

    def test_symlink_fifo_nonregular_and_mode_failures(self):
        for label in ("state_fifo", "state_symlink", "state_mode", "state_hardlink", "lock_fifo", "dir_symlink", "dir_mode"):
            with self.subTest(label):
                self.tearDown(); self.setUp()
                lp = os.path.join(self.ledger_dir, "ledger.lock")
                sp = os.path.join(self.ledger_dir, "ledger.json")
                if label == "state_fifo":
                    os.rename(sp, sp + ".x"); os.mkfifo(sp, 0o600)
                elif label == "state_symlink":
                    os.rename(sp, sp + ".x"); os.symlink(sp + ".x", sp)
                elif label == "state_mode":
                    os.chmod(sp, 0o644)
                elif label == "state_hardlink":
                    os.link(sp, sp + ".h")
                elif label == "lock_fifo":
                    os.rename(lp, lp + ".x"); os.mkfifo(lp, 0o600)
                elif label == "dir_symlink":
                    os.rename(self.ledger_dir, self.ledger_dir + ".real"); os.symlink(self.ledger_dir + ".real", self.ledger_dir)
                else:
                    os.chmod(self.ledger_dir, 0o755)
                t0 = time.monotonic()
                self.assertUnavailable("REPORT_INVALID")
                self.assertLess(time.monotonic() - t0, 2.0)
                if label == "dir_mode":
                    os.chmod(self.ledger_dir, 0o700)

    def test_coordinated_state_entry_replacement_during_read_is_invalid(self):
        done = []

        def hook(ev, res):
            if ev[0] == "read" and not done:
                done.append(1)
                # rename the validated file away (its link count stays 1) and put identical bytes
                # at the name: only a current-entry identity comparison can detect this
                sp = os.path.join(self.ledger_dir, "ledger.json")
                data = self.raw()
                os.rename(sp, sp + ".kept")
                with open(sp, "wb") as f:
                    f.write(data)
                os.chmod(sp, 0o600)

        with Trace(hook=hook):
            self.assertUnavailable("REPORT_INVALID")
        self.assertTrue(done)
        # ledger directory / lock entry replacement after the lock was taken
        self.tearDown(); self.setUp()
        done.clear()

        def hook2(ev, res):
            if ev[0] == "read" and not done:
                done.append(1)
                lp = os.path.join(self.ledger_dir, "ledger.lock")
                os.rename(lp, lp + ".gone"); open(lp, "wb").close(); os.chmod(lp, 0o600)

        with Trace(hook=hook2):
            self.assertUnavailable("REPORT_INVALID")

    def test_ledger_directory_entry_replaced_during_report_is_invalid(self):
        done = []

        def hook(ev, res):
            if ev[0] == "read" and not done:
                done.append(1)
                os.rename(self.ledger_dir, self.ledger_dir + ".kept")
                os.symlink(self.ledger_dir + ".kept", self.ledger_dir)

        with Trace(hook=hook):
            with self.assertRaises(LedgerReportUnavailableError) as c:
                read_recorded_report(self.root_fd, self.binding)
        self.assertEqual(c.exception.code, "REPORT_INVALID")
        self.assertTrue(done)
        # healthy control (fresh fixture): unmodified entry reports fine
        self.tearDown(); self.setUp()
        read_recorded_report(self.root_fd, self.binding)

    def test_short_read_changing_read_and_read_error(self):
        real_read = os.read
        state = {"mode": None}

        def fake(fd, n):
            data = real_read(fd, n)
            if state["mode"] == "short" and data and os.fstat(fd).st_size > 100 and stat.S_ISREG(os.fstat(fd).st_mode) \
                    and not state.get("did"):
                state["did"] = True
                return data[:10]  # then genuine continuation follows -> total still short? emulate truncation
            if state["mode"] == "eio":
                raise OSError(errno.EIO, "read fault")
            return data

        # truncation relative to validated size: read returns EOF early
        calls = {"n": 0}

        def early_eof(fd, n):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_read(fd, 10)
            return b""

        with patch("os.read", side_effect=early_eof):
            self.assertUnavailable("REPORT_INVALID")
        state["mode"] = "eio"
        with patch("os.read", side_effect=fake):
            self.assertUnavailable("REPORT_IO_FAILED")
        # growth during read (size changes after the validated fstat)
        def grow(fd, n):
            data = real_read(fd, n)
            if data and not state.get("grown"):
                state["grown"] = True
                with open(os.path.join(self.ledger_dir, "ledger.json"), "ab") as f:
                    f.write(b" ")
            return data
        with patch("os.read", side_effect=grow):
            self.assertUnavailable("REPORT_INVALID")
        # healthy control
        self.tearDown(); self.setUp()
        read_recorded_report(self.root_fd, self.binding)

    def test_unlock_and_close_faults_prevent_success_and_never_double_close(self):
        for mode, nth in (("unlock", 0), ("close", 1), ("close", 2), ("close", 3), ("open_state", 0)):
            with self.subTest(mode=mode, nth=nth):
                replacements, n = [], {"n": 0}
                real_close, real_open, real_flock = os.close, os.open, fcntl.flock

                def close_fault(fd):
                    n["n"] += 1
                    if mode == "close" and n["n"] == nth:
                        real_close(fd)
                        replacements.append((fd, real_open(os.devnull, os.O_RDONLY)))
                        raise OSError(errno.EIO, "close fault")
                    return real_close(fd)

                def open_fault(path, flags, *a, **kw):
                    if mode == "open_state" and path == "ledger.json":
                        raise OSError(errno.EIO, "open fault")
                    return real_open(path, flags, *a, **kw)

                def flock_fault(fd, op):
                    if mode == "unlock" and op == fcntl.LOCK_UN:
                        raise OSError(errno.EIO, "unlock fault")
                    return real_flock(fd, op)

                ps = [patch("os.close", side_effect=close_fault), patch("os.open", side_effect=open_fault),
                      patch("fcntl.flock", side_effect=flock_fault)]
                [p.start() for p in ps]
                try:
                    self.assertUnavailable("REPORT_IO_FAILED", check_lock=False)
                finally:
                    [p.stop() for p in ps]
                self.assertTrue(self.lock_free(), "lock released by close despite faults")
                for fd, r in replacements:
                    self.assertEqual(r, fd)
                    os.fstat(r)
                    os.close(r)
                if mode == "close":
                    self.assertEqual(len(replacements), 1)

    def test_borrowed_root_survives_every_path_and_bad_args(self):
        for _ in range(2):
            read_recorded_report(self.root_fd, self.binding)
            self.assertRootAlive()
        for bad in (True, -1, "x"):
            with self.assertRaises(LedgerReportUnavailableError):
                read_recorded_report(bad, self.binding)
        with self.assertRaises(LedgerReportUnavailableError):
            read_recorded_report(self.root_fd, None)
        # descriptor reuse: a freed number must never be closed by the reporter
        spare = os.open(os.devnull, os.O_RDONLY)
        self.assertUnavailable("REPORT_INVALID", binding=dataclasses.replace(self.binding, experiment_id="zz"))
        os.fstat(spare)
        os.close(spare)

    def test_error_text_has_no_state_or_exception_payload(self):
        with open(os.path.join(self.ledger_dir, "ledger.json"), "w") as f:
            f.write("SECRET_STATE_MARKER {")
        e = self.assertUnavailable("REPORT_INVALID")
        text = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        self.assertNotIn("SECRET_STATE_MARKER", text)
        self.assertNotIn("Corrupt", text)

    def test_identity_only_binding_error_cannot_establish_broker_revocation(self):
        # the standalone API reports a fixed code; it exposes no callback/revocation surface
        for name in ("revoke", "invalidate", "cancel", "callbacks"):
            self.assertFalse(hasattr(BudgetLedger, name))
            self.assertFalse(hasattr(LedgerBindingError, name))


def open_fds():
    return set(os.listdir("/proc/self/fd"))


class TestInterruptionAndMetadata(Base):
    """KeyboardInterrupt/SystemExit after acquisition, final owner/mode checks, close race, parser bound."""

    EXCS = (KeyboardInterrupt, SystemExit)

    def _raiser(self, exc, match, state):
        def hook(ev, res):
            if not state.get("fired") and match(ev):
                state["fired"] = True
                if state.get("replace_fd") and ev[0] == "close":
                    state["replacement"] = (ev[1], os.open(os.devnull, os.O_RDONLY))
                raise exc()
        return hook

    def _assert_binding_cleaned(self, exc, match, label, replace_fd=False):
        self.tearDown(); self.setUp()
        pend = self.h.reserve("req_pend", "sha256:p")
        before_fds = open_fds()
        state = {"replace_fd": replace_fd}
        with Trace(hook=self._raiser(exc, match, state)):
            with self.assertRaises(exc):
                self.h.verify_binding(self.root_fd, self.binding)
        self.assertTrue(state.get("fired"), label)
        repl = state.get("replacement")
        after = open_fds()
        if repl:
            self.assertEqual(repl[0], repl[1], "same number reused")
            os.fstat(repl[1])  # not closed again
            os.close(repl[1])
            after = open_fds()
        # lease fd for the pending reservation was released by the revoked handle
        self.assertEqual(after - before_fds, set(), label)
        self.assertTrue(self.h.is_handle_disabled)
        self.assertIsNone(self.h._held_lease_fd)
        self.assertTrue(self.lock_free(), "transaction lock reacquirable")
        self.assertIsNotNone(json.loads(self.raw())["pending_reservation"], "pending retained")
        self.assertRootAlive()
        with self.assertRaises(LedgerBindingError) as c:
            self.h.verify_binding(self.root_fd, self.binding)
        self.assertEqual(str(c.exception), "BINDING_DISABLED")  # mutex was released, not left busy

    def test_binding_interruption_points_clean_up_and_revoke(self):
        points = {
            "post_lock": lambda ev: ev[0] == "flock" and ev[2] == (fcntl.LOCK_EX | fcntl.LOCK_NB),
            "final_checks": lambda ev: ev[0] == "stat" and ev[1] == "ledger.lock",
            "unlock": lambda ev: ev[0] == "flock" and ev[2] == fcntl.LOCK_UN,
            "first_close": lambda ev: ev[0] == "close",
        }
        for exc in self.EXCS:
            for label, match in points.items():
                with self.subTest(exc=exc.__name__, point=label):
                    self._assert_binding_cleaned(exc, match, label, replace_fd=(label == "first_close"))

    def test_binding_interruption_during_failure_cleanup_still_visits_every_resource(self):
        for exc in self.EXCS:
            with self.subTest(exc=exc.__name__):
                self.tearDown(); self.setUp()
                self.h.reserve("req_pend", "sha256:p")
                other = os.path.join(self.tmp.name, "other")
                BudgetLedger.initialize(other).close()
                self.h._ledger_dir = other  # forces a normal BINDING_INVALID after fds are open
                before = open_fds()
                st = {}
                with Trace(hook=self._raiser(exc, lambda ev: ev[0] == "close", st)):
                    with self.assertRaises(exc):
                        self.h.verify_binding(self.root_fd, self.binding)
                self.assertEqual(open_fds() - before, set())
                self.assertTrue(self.h.is_handle_disabled)
                self.assertIsNone(self.h._held_lease_fd)
                self.assertTrue(self.lock_free())

    def test_report_interruption_points_clean_up(self):
        points = {
            "post_lock": lambda ev: ev[0] == "flock" and ev[2] == (fcntl.LOCK_SH | fcntl.LOCK_NB),
            "mid_read": lambda ev: ev[0] == "read",
            "final_checks": lambda ev: ev[0] == "stat" and ev[1] == "ledger.lock",
            "unlock": lambda ev: ev[0] == "flock" and ev[2] == fcntl.LOCK_UN,
            "first_close": lambda ev: ev[0] == "close",
        }
        for exc in self.EXCS:
            for label, match in points.items():
                with self.subTest(exc=exc.__name__, point=label):
                    self.tearDown(); self.setUp()
                    self.h.reserve("req_pend", "sha256:p")
                    before_fds, before = open_fds(), self.snapshot()
                    st = {"replace_fd": label == "first_close"}
                    with Trace(hook=self._raiser(exc, match, st)):
                        with self.assertRaises(exc):
                            read_recorded_report(self.root_fd, self.binding)
                    self.assertTrue(st.get("fired"))
                    repl = st.get("replacement")
                    if repl:
                        self.assertEqual(repl[0], repl[1])
                        os.fstat(repl[1]); os.close(repl[1])
                    self.assertEqual(open_fds() - before_fds, set())
                    self.assertTrue(self.lock_free())
                    self.assertEqual(self.snapshot(), before)
                    self.assertRootAlive()
                    self.assertFalse(self.h.is_handle_disabled)  # reporter has no handle to revoke
                    # healthy control after the interruption
                    self.assertEqual(read_recorded_report(self.root_fd, self.binding).recorded_pending_micros, 1_100_000)

    def test_busy_mutex_still_neither_poisons_nor_releases_under_new_cleanup(self):
        entered, release = threading.Event(), threading.Event()
        real = BudgetLedger._guarded_state

        def slow(self_, dir_fd):
            st = real(self_, dir_fd)
            entered.set(); release.wait(10)
            return st

        res = {}
        with patch.object(BudgetLedger, "_guarded_state", slow):
            t = threading.Thread(target=lambda: res.setdefault("p", self.h.reserve("r", "sha256:r")))
            t.start(); entered.wait(10)
            with self.assertRaises(LedgerBindingError) as c:
                self.h.verify_binding(self.root_fd, self.binding)
            self.assertEqual(str(c.exception), "BINDING_BUSY")
            self.assertFalse(self.h._poisoned)
            release.set(); t.join(10)
        self.assertIn("p", res)
        self.assertIsNotNone(self.h._held_lease_fd)

    # ---- final owner/mode checks ------------------------------------------
    def _chmod_after_lock(self, target, mode, lock_op):
        done = []

        def hook(ev, res):
            if ev[0] == "flock" and ev[2] == lock_op and not done:
                done.append(1)
                os.chmod(target, mode)

        return hook

    def test_final_checks_reject_lock_or_root_mode_change_after_real_lock(self):
        lp = lambda: os.path.join(self.ledger_dir, "ledger.lock")
        cases = {
            "lock_0666": (lambda: lp(), 0o666),
            "lock_0644": (lambda: lp(), 0o644),
            "ledger_dir_0750": (lambda: self.ledger_dir, 0o750),
            "root_0750": (lambda: self.root, 0o750),
        }
        for label, (target, mode) in cases.items():
            with self.subTest(label=label, api="binding"):
                self.tearDown(); self.setUp()
                self.h.reserve("req_pend", "sha256:p")
                with Trace(hook=self._chmod_after_lock(target(), mode, fcntl.LOCK_EX | fcntl.LOCK_NB)):
                    with self.assertRaises(LedgerBindingError) as c:
                        self.h.verify_binding(self.root_fd, self.binding)
                self.assertEqual(str(c.exception), "BINDING_INVALID")
                self.assertTrue(self.h.is_handle_disabled)
                os.chmod(self.root, 0o700)
            with self.subTest(label=label, api="report"):
                self.tearDown(); self.setUp()
                with Trace(hook=self._chmod_after_lock(target(), mode, fcntl.LOCK_SH | fcntl.LOCK_NB)):
                    with self.assertRaises(LedgerReportUnavailableError) as c:
                        read_recorded_report(self.root_fd, self.binding)
                self.assertEqual(str(c.exception), "REPORT_INVALID")
                os.chmod(self.root, 0o700)
        # healthy controls with the same hook but a no-op mode
        self.tearDown(); self.setUp()
        with Trace(hook=self._chmod_after_lock(lp(), 0o600, fcntl.LOCK_EX | fcntl.LOCK_NB)):
            self.assertEqual(self.h.verify_binding(self.root_fd, self.binding), self.binding)
        with Trace(hook=self._chmod_after_lock(lp(), 0o600, fcntl.LOCK_SH | fcntl.LOCK_NB)):
            read_recorded_report(self.root_fd, self.binding)

    # ---- maintained close race ---------------------------------------------
    def test_concurrent_status_and_close_are_serialized_and_binding_sees_busy(self):
        entered, release = threading.Event(), threading.Event()
        real = BudgetLedger._guarded_state

        def slow(self_, dir_fd):
            st = real(self_, dir_fd)
            entered.set(); release.wait(10)
            return st

        out = {}
        closed = threading.Event()
        with patch.object(BudgetLedger, "_guarded_state", slow):
            t_status = threading.Thread(target=lambda: out.setdefault("status", self.h.get_status()))
            t_status.start()
            self.assertTrue(entered.wait(10))

            def do_close():
                self.h.close()
                closed.set()

            t_close = threading.Thread(target=do_close)
            t_close.start()
            self.assertFalse(closed.wait(0.5), "close() must wait for the in-flight status")
            with self.assertRaises(LedgerBindingError) as c:
                self.h.verify_binding(self.root_fd, self.binding)
            self.assertEqual(str(c.exception), "BINDING_BUSY")
            self.assertFalse(self.h._poisoned, "busy refusal must not poison while close is queued")
            release.set()
            t_status.join(10); t_close.join(10)
        self.assertTrue(closed.is_set())
        self.assertFalse(out["status"].halted)  # the in-flight operation completed normally
        self.assertTrue(self.h.is_handle_disabled)
        self.assertEqual(self.h._poison_reason, "HANDLE_CLOSED")
        with self.assertRaises(LedgerBindingError) as c:
            self.h.verify_binding(self.root_fd, self.binding)
        self.assertEqual(str(c.exception), "BINDING_DISABLED")

    # ---- pre-parser depth bound --------------------------------------------
    def test_depth_five_never_reaches_json_parser(self):
        import research.t2a.openai_budget.report as report_mod
        calls = []
        real = report_mod._safe_json_loads

        def spy(text):
            calls.append(len(text))
            return real(text)

        path = os.path.join(self.ledger_dir, "ledger.json")
        good = self.raw()
        with open(path, "wb") as f:
            f.write(json.dumps({"a": [[[[1]]]]}).encode())  # root dict depth 1 ... list depth 5
        os.chmod(path, 0o600)
        with patch.object(report_mod, "_safe_json_loads", spy):
            with self.assertRaises(LedgerReportUnavailableError) as c:
                read_recorded_report(self.root_fd, self.binding)
        self.assertEqual(str(c.exception), "REPORT_INVALID")
        self.assertEqual(calls, [], "depth-5 input rejected before any JSON parsing")
        with open(path, "wb") as f:
            f.write(good)
        os.chmod(path, 0o600)
        with patch.object(report_mod, "_safe_json_loads", spy):
            read_recorded_report(self.root_fd, self.binding)  # healthy control reaches the parser
        self.assertEqual(len(calls), 1)
        # braces/brackets inside strings do not count as nesting
        st = json.loads(good)
        st["journal"][0]["experiment_id"] = st["experiment_id"]


class TestLeaseReleaseOwnership(Base):
    """_release_lease: ownership detached before unlock/close; exact-number FD reuse safe."""

    def _lease(self):
        self.h.reserve("req_lease", "sha256:lease")
        return self.h._held_lease_fd

    def test_close_then_interrupt_with_exact_fd_reuse_never_closes_replacement(self):
        for exc in (KeyboardInterrupt, SystemExit):
            with self.subTest(exc=exc.__name__):
                self.tearDown(); self.setUp()
                lease = self._lease()
                real_close, state = os.close, {}

                def close(fd):
                    if fd == lease and not state.get("fired"):
                        state["fired"] = True
                        real_close(fd)
                        spare = os.open(os.devnull, os.O_RDONLY)
                        if spare != lease:
                            os.dup2(spare, lease)
                            real_close(spare)
                        raise exc()
                    return real_close(fd)

                with patch("os.close", close):
                    with self.assertRaises(exc):
                        self.h.verify_binding(self.root_fd, dataclasses.replace(self.binding, experiment_id="other"))
                self.assertTrue(state["fired"])
                self.assertTrue(self.h.is_handle_disabled)
                self.assertIsNone(self.h._held_lease_fd, "stale lease number must not remain")
                os.fstat(lease)  # replacement alive
                self.h.close()   # must not touch the replacement
                os.fstat(lease)
                os.close(lease)
                self.assertIsNotNone(json.loads(self.raw())["pending_reservation"], "pending retained")
                self.assertRootAlive()

    def test_interrupt_after_real_unlock_still_closes_descriptor_once(self):
        for exc in (KeyboardInterrupt, SystemExit):
            with self.subTest(exc=exc.__name__):
                self.tearDown(); self.setUp()
                lease = self._lease()
                real_flock, state, closes = fcntl.flock, {}, []
                real_close = os.close

                def flock(fd, op):
                    r = real_flock(fd, op)
                    if fd == lease and op == fcntl.LOCK_UN and not state.get("fired"):
                        state["fired"] = True
                        raise exc()
                    return r

                def close(fd):
                    if fd == lease:
                        closes.append(fd)
                    return real_close(fd)

                before = open_fds()
                with patch("fcntl.flock", flock), patch("os.close", close):
                    with self.assertRaises(exc):
                        self.h._release_lease()
                self.assertEqual(closes, [lease], "closed exactly once despite interrupted unlock")
                self.assertIsNone(self.h._held_lease_fd)
                self.assertEqual(open_fds(), before - {str(lease)})
                self.h.close()  # no double close
                self.assertEqual(closes, [lease])

    def test_ordinary_oserror_behavior_and_healthy_release_preserved(self):
        lease = self._lease()
        real_flock, real_close = fcntl.flock, os.close
        seen = []

        def flock(fd, op):
            if op == fcntl.LOCK_UN:
                raise OSError(errno.EIO, "unlock")
            return real_flock(fd, op)

        def close(fd):
            if fd == lease:
                seen.append(fd)
                real_close(fd)
                raise OSError(errno.EIO, "close")
            return real_close(fd)

        with patch("fcntl.flock", flock), patch("os.close", close):
            self.h._release_lease()  # ordinary OSErrors are swallowed as before
        self.assertEqual(seen, [lease])
        self.assertIsNone(self.h._held_lease_fd)
        # healthy control: normal release then idempotent second call
        self.tearDown(); self.setUp()
        lease = self._lease()
        self.h._release_lease()
        self.h._release_lease()
        with self.assertRaises(OSError):
            os.fstat(lease)
        # no authority revival: after release the pending reservation cannot be settled by this handle
        self.assertIsNotNone(json.loads(self.raw())["pending_reservation"])
        self.assertTrue(self.lock_free())


if __name__ == "__main__":
    unittest.main()
