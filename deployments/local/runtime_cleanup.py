"""Best-effort runtime shutdown with explicit failures and retryable ownership."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


class CleanupError(RuntimeError):
    def __init__(self, failures):
        self.failures = failures
        super().__init__("cleanup incomplete: " + "; ".join(f"{step}: {error}" for step, error in failures))


class Cleanup:
    def __init__(self):
        self.failures = []

    def attempt(self, step, action):
        try:
            action()
            return True
        except Exception as error:
            self.failures.append((step, error))
            return False

    def finish(self):
        if self.failures:
            raise CleanupError(self.failures)


def cleanup_after_error(error, cleanup):
    """Keep the original exception as the cause if rollback also fails."""
    try:
        cleanup()
    except Exception as failure:
        raise RuntimeError(f"{error}; rollback also failed: {failure}") from error


def stop_process(proc, cleanup, label, timeout):
    """Confirm exit, including after SIGKILL; retain a live process for retry."""
    try:
        running = proc.poll() is None
    except Exception as error:
        cleanup.failures.append((f"inspect {label}", error))
        running = True
    if running:
        cleanup.attempt(f"terminate {label}", proc.terminate)
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        pass  # A bounded grace period expiring is expected when kill is needed.
    except Exception as error:
        cleanup.failures.append((f"wait for {label}", error))
    cleanup.attempt(f"kill {label}", proc.kill)
    try:
        proc.wait(timeout=5)
        return True
    except Exception as error:
        cleanup.failures.append((f"confirm {label} exit after kill", error))
        return False


def close_streams(proc, cleanup, label):
    # Never read to EOF here: descendants can retain pipe writers after the
    # tracked process exits. Closing our descriptors does not wait for EOF.
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(proc, name, None)
        if stream is not None:
            cleanup.attempt(f"close {label} {name}", stream.close)


def stop_session(session, broker_timeout, report_broker=False):
    cleanup = Cleanup()
    # Revoke authority even when Docker cannot be reached. Failed revocation
    # keeps the AgentSession (and its ID) attached for a later stop() retry.
    if session.agent_session is not None:
        identity = session.agent_session.session_id
        if cleanup.attempt(f"revoke owner session {identity}", session.agent_session.close):
            session.agent_session = None
    if session.broker is not None:
        broker = session.broker
        stopped = stop_process(broker, cleanup, "host broker", broker_timeout)
        if stopped and report_broker:
            def summary():
                # Preserve the native launchers' final broker summary, but
                # bound pipe draining even when a descendant retained a writer.
                stdout, _ = broker.communicate(timeout=1)
                for line in (stdout or "").splitlines()[-1:]:
                    session.out("broker: " + line[:300])
            cleanup.attempt("collect broker summary", summary)
        close_streams(broker, cleanup, "host broker")
        if stopped:
            session.broker = None
    log = getattr(session, "broker_log", None)
    if log is not None and cleanup.attempt("close broker log", log.close):
        session.broker_log = None
    cleanup.attempt("stop executor", session.executor.stop)
    if session.sockdir is not None:
        if session.broker is None and session.executor.containers_stopped:
            def remove_socket_directory():
                try:
                    shutil.rmtree(session.sockdir)
                except FileNotFoundError:
                    pass
            if cleanup.attempt(f"remove broker directory {session.sockdir}", remove_socket_directory):
                session.sockdir = None
        else:
            cleanup.failures.append((f"retain broker directory {session.sockdir}",
                                     RuntimeError("broker or container shutdown is unconfirmed; retry stop")))
    session_dir = getattr(session, "dir", None)
    snapshot_gone = True
    if session_dir is not None:
        runtime_bin = Path(session_dir) / "runtime_bin"
        if runtime_bin.exists() or runtime_bin.is_symlink():
            if session.executor.containers_stopped:
                def remove_runtime_bin():
                    try:
                        if runtime_bin.is_symlink():
                            runtime_bin.unlink()
                        else:
                            shutil.rmtree(runtime_bin)
                    except FileNotFoundError:
                        pass
                snapshot_gone = cleanup.attempt(f"remove runtime snapshot {runtime_bin}", remove_runtime_bin)
            else:
                snapshot_gone = False
                cleanup.failures.append((f"retain runtime snapshot {runtime_bin}",
                                         RuntimeError("container shutdown is unconfirmed; retry stop")))
    # Keep the session lock while a snapshot remains, so no other launcher sweeps it.
    lock = getattr(session, "runtime_lock", None)
    if lock is not None and snapshot_gone and cleanup.attempt("release runtime snapshot lock", lock.close):
        session.runtime_lock = None
    cleanup.finish()


def finish_cli_cleanup(session, transcript, status):
    """Report every failure without masking a pending run/startup exception."""
    cleanup = Cleanup()
    if transcript is not None:
        cleanup.attempt("close transcript", transcript.close)
    cleanup.attempt("stop session", session.stop)
    if cleanup.failures:
        print(str(CleanupError(cleanup.failures)), file=sys.stderr)
        return status or 1
    return status
