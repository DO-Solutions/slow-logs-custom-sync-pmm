#!/usr/bin/env python3
"""
MySQL Slow Query Log Reconstruction Daemon
Tails syslog-forwarded MySQL slow query logs from DigitalOcean Managed Databases,
reconstructs multi-line blocks keyed by (source_host, block_id), and appends
complete entries to the native slow query log for PMM QAN consumption. Saves
its place on stop, so a restart picks up exactly where it left off.

Deploys to: /var/log/mysql_sink/bin/transform_logs.py
Managed by: slow-query-sink.service (systemd)
"""

import os
import re
import sys
import json
import time
import signal
import hashlib
import logging

COMBINED_FILE = "/var/log/mysql_sink/incoming/combined_mysql.log"
SLOW_LOG_OUTPUT = "/var/log/mysql_sink/processed/native_slow_query.log"
POLL_INTERVAL = 0.1   # seconds between reads when no new data
BLOCK_TTL     = 30.0  # seconds before an incomplete block is discarded

# Where the daemon saves its place in COMBINED_FILE (see "Saved position"
# below). The directory is the unit's StateDirectory=: created by systemd,
# owned by mysqlsink, 0700 because saved in-flight blocks hold SQL text.
STATE_FILE        = "/var/lib/mysql_sink/slow-query-sink/position.json"
STATE_VERSION     = 1
MAX_STATE_BYTES   = 16 << 20  # bigger than this, in-flight blocks aren't saved
FINGERPRINT_BYTES = 256       # bytes before the saved offset that must still match

# Defense-in-depth bounds on untrusted syslog input (mTLS gates the sender, but
# the parser still treats every line as hostile and refuses to grow unbounded).
MAX_BLOCKS          = 10000    # distinct in-flight blocks before new ones are dropped
MAX_LINES_PER_BLOCK = 1000     # fragments retained per block
MAX_PAYLOAD_BYTES   = 1 << 20  # max reconstructed payload kept per line (1 MiB)
MAX_LINE_BYTES      = 1 << 20  # ignore absurdly long raw input lines (1 MiB)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

# Source host is the field after the timestamp. DO sends RFC3164 on the wire, but
# what we parse is rsyslog's *file* output, whose shape depends on the omfile
# template — so accept every shape it can realistically have:
#   RSYSLOG_FileFormat (setup.sh pins this):  2026-11-12T21:53:42+00:00 host mysqld[241]: ...
#   RSYSLOG_TraditionalFileFormat:            Nov 12 21:53:42 host mysqld[241]: ...
#   raw RFC3164 with PRI:                     <134>Nov 12 21:53:42 host mysqld[241]: ...
# (An earlier version only matched the last form, which rsyslog never writes to a
# file, so every line was keyed to host "unknown" and per-host block separation
# silently didn't happen.)
SYSLOG_HOST_RE = re.compile(
    r'^(?:<\d+>)?(?:\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})|\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+'
)
SEQ_RE = re.compile(r'\[(\d+)-(\d+)\]')

_running = True

# Throttle drop warnings so a flood of bad input can't itself flood the journal:
# at most one line per reason per DROP_LOG_INTERVAL, carrying the running count.
# (Time-based rather than every-Nth, so a rare drop is never silent: logging
# only the 1st and every 1000th hid the 2nd through 999th.)
DROP_LOG_INTERVAL = 60.0
_drop_counts = {}
_drop_logged_at = {}


def _warn_drop(reason):
    n = _drop_counts.get(reason, 0) + 1
    _drop_counts[reason] = n
    now = time.monotonic()
    last = _drop_logged_at.get(reason)
    if last is None or now - last >= DROP_LOG_INTERVAL:
        _drop_logged_at[reason] = now
        log.warning("Dropping input: %s (occurrences=%d)", reason, n)


def _handle_signal(signum, frame):
    global _running
    _running = False


def _get_inode(path):
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return None


def _open_tail(path):
    """Open path for tailing (seeked to end). Blocks until file exists."""
    while _running:
        try:
            # Binary: _LineReader decodes each line only once it's complete.
            f = open(path, "rb")
            inode = _get_inode(path)
            f.seek(0, 2)
            return f, inode
        except FileNotFoundError:
            time.sleep(1)
    return None, None


def _open_output(path):
    """Open the processed log for appending; return (file, inode of what we opened).
    The inode is remembered so run() can notice when logrotate (or anything else)
    has moved the file out from under us — see _reopen_output_if_rotated."""
    f = open(path, "a")
    return f, os.fstat(f.fileno()).st_ino


class _LineReader:
    """Hand out only complete lines from a file rsyslog is still appending to.

    readline() at end-of-file returns whatever is there, and the kernel copies a
    write() into the file one 4 KiB page at a time, so for an instant the file
    can end at a page boundary part-way through a line. A reader that polls at
    that instant gets half a line now and the rest on its next read. Parsed as
    two lines, neither half is valid: the line is lost (so its whole block is
    dropped for a gap), truncated, or filed under host "unknown", depending on
    where the cut falls. So a fragment is held back until its newline arrives.
    (Seen live: a busy-polling reader on a sink caught ~3 such cuts a minute,
    and the daemon, polling 10x/s, lost a slow query this way every few hours
    on each test sink, each time at a line straddling a page boundary.)

    Reads bytes and decodes each finished line itself, because a text-mode
    reader would turn a multi-byte character split by such a cut into U+FFFD.
    errors="replace" still surfaces genuinely malformed bytes as U+FFFD instead
    of silently dropping them, so tampering or corruption stays visible.
    """

    def __init__(self, f):
        self.f = f
        self.pending = b""     # start of a line whose newline hasn't arrived yet
        self.skipping = False  # inside an oversized line: discard up to its newline

    def readline(self):
        """The next complete line as str, or "" if none is complete yet."""
        while True:
            # Bounded read: an endless line can't grow memory past MAX_LINE_BYTES.
            chunk = self.f.readline(MAX_LINE_BYTES + 1 - len(self.pending))
            if not chunk:
                return ""
            if self.skipping:
                self.skipping = not chunk.endswith(b"\n")
                continue
            line = self.pending + chunk
            if not line.endswith(b"\n"):
                if len(line) > MAX_LINE_BYTES:
                    _warn_drop("oversized line")
                    self.pending, self.skipping = b"", True
                else:
                    self.pending = line
                continue
            self.pending = b""
            return line.decode("utf-8", errors="replace")


def _reopen_output_if_rotated(path, out_file, out_inode):
    """Reopen the processed log if the file at `path` is no longer the one we
    hold open. Without this, after logrotate renames native_slow_query.log to
    .1 and creates a fresh empty file, we'd keep appending to .1 (and later to a
    deleted .2.gz inode) while pmm-agent tails the new, forever-empty file —
    i.e. QAN silently stops one day after deployment.

    If the path is missing entirely (deleted, or caught between logrotate's
    rename and create), recreate it ourselves; the unit's UMask plus the setgid
    processed/ directory give it the same 0640 mysqlsink:adm that logrotate's
    `create` line would."""
    if _get_inode(path) == out_inode:
        return out_file, out_inode
    log.info("Output file %s was rotated or removed, reopening", path)
    out_file.close()
    return _open_output(path)


def _finalize_block(key, blocks, block_times, out_file, stale=False):
    """Write out a block once we're sure no more lines are coming for it: either
    the same host started a new block (see active_block in _process_line), or it
    went stale. A block's true line count isn't known up front (it varies with
    SQL length), so completeness can't be checked line-by-line as data arrives —
    only at the moment we decide the block is done."""
    lines = blocks.pop(key, None)
    block_times.pop(key, None)
    if not lines:
        return
    max_line = max(lines)
    if len(lines) != max_line or not all(i in lines for i in range(1, max_line + 1)):
        if stale:
            log.warning("Discarding stale incomplete block host=%s block_id=%s", *key)
        else:
            _warn_drop("finalized block has gaps")
        return
    rebuilt = [lines[i] for i in range(1, max_line + 1)]
    out_file.write("\n".join(rebuilt) + "\n\n")
    out_file.flush()


def _process_line(line, blocks, block_times, active_block, out_file):
    if len(line) > MAX_LINE_BYTES:
        _warn_drop("oversized line")
        return

    if "[SlowQuery]" not in line:
        return

    host_match = SYSLOG_HOST_RE.match(line)
    source_host = host_match.group(1) if host_match else "unknown"

    seq_match = SEQ_RE.search(line)
    if not seq_match:
        return

    block_id = int(seq_match.group(1))
    line_num  = int(seq_match.group(2))

    # Everything after the FIRST [block-line] tag is payload. (maxsplit matters:
    # SQL text that happens to contain the same "[12-3]" string must not be
    # truncated at it.)
    payload = line[seq_match.end():].strip()
    if len(payload) > MAX_PAYLOAD_BYTES:
        _warn_drop("oversized payload")
        return

    key = (source_host, block_id)

    # A per-host slow-log writer is serialized, so line 1 of a new block_id can
    # only appear once the previous block for that same host has fully arrived —
    # that's the actual "block is done" signal, not any line-count arithmetic.
    prev_active = active_block.get(source_host)
    if line_num == 1 and prev_active is not None and prev_active != key:
        _finalize_block(prev_active, blocks, block_times, out_file)

    if key not in blocks:
        if len(blocks) >= MAX_BLOCKS:
            _warn_drop("max in-flight blocks reached")
            return
        blocks[key] = {}
        block_times[key] = time.monotonic()
    elif line_num not in blocks[key] and len(blocks[key]) >= MAX_LINES_PER_BLOCK:
        _warn_drop("max lines per block reached")
        return
    blocks[key][line_num] = payload
    active_block[source_host] = key


def _purge_stale(blocks, block_times, active_block, out_file):
    """Finalize blocks older than BLOCK_TTL. Normally a block is finalized when
    its host starts the next one (see _process_line), but the LAST block before
    a quiet period never gets that signal — so it has to be finalized here, and
    written out if it's complete. (Discarding it instead, as this used to, lost
    the final slow query of every burst on a quiet DB.)"""
    now   = time.monotonic()
    stale = [k for k, ts in block_times.items() if now - ts > BLOCK_TTL]
    for key in stale:
        host = key[0]
        if active_block.get(host) == key:
            del active_block[host]
        _finalize_block(key, blocks, block_times, out_file, stale=True)


# --- Saved position ---------------------------------------------------------
#
# Starting at the end of COMBINED_FILE, as this daemon used to on every start,
# skips whatever rsyslog wrote while the daemon was down, and every block that
# was mid-delivery when it stopped. (Seen on a test sink: an unattended upgrade
# restarted rsyslog, the daemon restarted with it via Requires=, and about a
# second of slow queries never reached QAN.)
#
# So whenever the daemon stops in a way it can clean up after (SIGTERM from
# systemd, or an exception), it saves its place: the input file's inode, the
# offset just past the last complete line it consumed, a hash of the bytes
# before that offset (so a new file that reuses the inode number isn't taken
# for the old one), and its in-flight blocks. The next start resumes exactly
# there, so nothing is skipped and nothing is written twice.
#
# A run that's killed outright (SIGKILL, OOM, power loss) can't save. To keep
# the next start from resuming a position this run has already moved past
# (which would write those queries twice), the saved position is replaced by
# a "running" marker as soon as it's been used. Finding the marker, a start
# falls back to the end of the file, as before, and logs a warning saying so.


def _fingerprint(fd, offset):
    """Hash of the FINGERPRINT_BYTES before offset, or None if the file is
    shorter than offset now. pread, so the file position is left alone."""
    start = max(0, offset - FINGERPRINT_BYTES)
    data = os.pread(fd, offset - start, start)
    if len(data) != offset - start:
        return None
    return hashlib.sha256(data).hexdigest()


def _write_state(data):
    """Atomically replace STATE_FILE with data (a JSON string). Temp file,
    fsync, rename: a crash mid-write leaves the previous file intact."""
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, STATE_FILE)


def _parse_state(state):
    """Check a saved state and rebuild the parser's structures from it. The
    file is the daemon's own, but a damaged one must cost a warning, not a
    crash loop, so it's held to the same bounds as live input."""
    def need(ok, what):
        if not ok:
            raise ValueError("bad " + what)

    for k in ("ino", "offset"):
        need(type(state[k]) is int and state[k] >= 0, k)
    need(isinstance(state["fingerprint"], str), "fingerprint")
    need(isinstance(state["skipping"], bool), "skipping")
    entries = state["blocks"]
    need(isinstance(entries, list) and len(entries) <= MAX_BLOCKS, "blocks")

    now = time.monotonic()
    blocks, block_times, active_block = {}, {}, {}
    for host, block_id, age, lines in entries:
        need(isinstance(host, str) and type(block_id) is int and isinstance(age, (int, float))
             and isinstance(lines, dict) and len(lines) <= MAX_LINES_PER_BLOCK, "block")
        key = (host, block_id)
        blocks[key] = {}
        for n, payload in lines.items():
            need(isinstance(payload, str) and len(payload) <= MAX_PAYLOAD_BYTES, "payload")
            blocks[key][int(n)] = payload
        # Age, not a timestamp: monotonic time doesn't carry across a restart.
        # Time spent stopped doesn't count towards BLOCK_TTL; the rest of the
        # block is waiting in the file.
        block_times[key] = now - max(0.0, age)
    for host, block_id in state["active"]:
        need((host, block_id) in blocks, "active block")
        active_block[host] = (host, block_id)
    return {"ino": state["ino"], "offset": state["offset"], "fingerprint": state["fingerprint"],
            "skipping": state["skipping"], "blocks": blocks, "block_times": block_times,
            "active_block": active_block}


def _load_state():
    """The position saved by the last clean stop, or None (reason logged) if
    there's none to use: first start, a run killed before it could save, or a
    damaged file."""
    skipped = ("starting at the end of %s, so slow queries logged while the daemon "
               "was stopped are skipped" % COMBINED_FILE)
    try:
        with open(STATE_FILE, "rb") as fh:
            raw = fh.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        log.info("No saved position (first start); starting at the end of %s", COMBINED_FILE)
        return None
    except OSError as e:
        log.warning("Can't read saved position %s (%s); %s", STATE_FILE, e, skipped)
        return None
    try:
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("larger than %d bytes" % MAX_STATE_BYTES)
        state = json.loads(raw)
        if state.get("version") != STATE_VERSION:
            raise ValueError("unknown version %r" % (state.get("version"),))
        if state.get("running"):
            log.warning("The previous run stopped without saving its position (killed, or out "
                        "of memory?); %s", skipped)
            return None
        return _parse_state(state)
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        log.warning("Saved position %s is unusable (%s); %s", STATE_FILE, e, skipped)
        return None


def _open_input(saved):
    """Open COMBINED_FILE where the last run stopped: in the file itself, or
    in its .1 if logrotate rotated it meanwhile (run() then moves on to the
    new file as it does after any rotation). Without a saved position, open it
    at the end. Returns (file, inode, reader, blocks, block_times,
    active_block); file is None if the daemon was told to stop while waiting
    for the input to exist."""
    if saved is not None:
        for path in (COMBINED_FILE, COMBINED_FILE + ".1"):
            try:
                f = open(path, "rb")
            except FileNotFoundError:
                continue
            ino = os.fstat(f.fileno()).st_ino
            if ino == saved["ino"] and _fingerprint(f.fileno(), saved["offset"]) == saved["fingerprint"]:
                f.seek(saved["offset"])
                reader = _LineReader(f)
                reader.skipping = saved["skipping"]
                log.info("Resuming %s at byte %d with %d in-flight blocks",
                         path, saved["offset"], len(saved["blocks"]))
                return f, ino, reader, saved["blocks"], saved["block_times"], saved["active_block"]
            f.close()
        # Its in-flight blocks can't be finished now, so they're not restored:
        # one that happens to look gap-free would be written truncated.
        log.warning("The file the saved position is in is gone or has changed (rotated more "
                    "than once while the daemon was stopped?); reading %s from its start, so "
                    "slow queries logged in between are skipped", COMBINED_FILE)
    f, ino = _open_tail(COMBINED_FILE)
    if f is None:
        return None, None, None, {}, {}, {}
    if saved is not None:
        f.seek(0)
    return f, ino, _LineReader(f), {}, {}, {}


def _mark_running():
    """Replace the saved position with the "running" marker (see above), now
    that it's been used."""
    try:
        _write_state(json.dumps({"version": STATE_VERSION, "running": True}))
        return
    except OSError as e:
        log.warning("Can't write %s (%s); removing the used position instead", STATE_FILE, e)
    try:
        os.remove(STATE_FILE)  # still works when the disk is too full to write
    except FileNotFoundError:
        pass
    except OSError as e:
        log.error("Can't remove the used position %s either (%s): if this run is killed, the "
                  "next start writes everything since that position twice", STATE_FILE, e)


def _save_state(f, reader, blocks, block_times, active_block):
    """Save where this run stopped. Called on the way out of run(); doesn't raise."""
    try:
        # A fragment held back by the reader is re-read whole next time.
        offset = f.tell() - len(reader.pending)
        ino = os.fstat(f.fileno()).st_ino
        now = time.monotonic()
        state = {
            "version": STATE_VERSION, "ino": ino, "offset": offset,
            "fingerprint": _fingerprint(f.fileno(), offset), "skipping": reader.skipping,
            "blocks": [[host, block_id, now - block_times.get((host, block_id), now),
                        {str(n): p for n, p in lines.items()}]
                       for (host, block_id), lines in blocks.items()],
            "active": [list(key) for key in active_block.values()],
        }
        data = json.dumps(state)
        if len(data) > MAX_STATE_BYTES:
            log.warning("%d in-flight blocks are too large to save; they're lost", len(blocks))
            state["blocks"], state["active"] = [], []
            data = json.dumps(state)
        _write_state(data)
    except (OSError, ValueError) as e:
        log.error("Couldn't save position to %s (%s); the next start begins at the end of %s, "
                  "skipping whatever is logged until then", STATE_FILE, e, COMBINED_FILE)
        return
    log.info("Saved position: byte %d of %s, %d in-flight blocks", offset, f.name, len(blocks))


def run():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    os.makedirs(os.path.dirname(SLOW_LOG_OUTPUT), exist_ok=True)

    log.info("Starting slow query log daemon, tailing %s", COMBINED_FILE)

    # blocks:       (host, block_id) -> {line_num: payload}
    # block_times:  (host, block_id) -> monotonic timestamp of first line seen
    # active_block: host -> the (host, block_id) key currently being written
    f, current_inode, reader, blocks, block_times, active_block = _open_input(_load_state())
    if f is None:
        return

    try:
        out_file, out_inode = _open_output(SLOW_LOG_OUTPUT)
    except BaseException:
        f.close()
        raise
    # Only now, so a start that fails to open the output keeps the saved
    # position for the next attempt.
    _mark_running()
    try:
        while _running:
            line = reader.readline()

            if line:
                _process_line(line, blocks, block_times, active_block, out_file)
            else:
                new_inode = _get_inode(COMBINED_FILE)
                if new_inode is None or new_inode != current_inode:
                    log.info("File rotation detected, reopening %s", COMBINED_FILE)
                    # A fragment left in the old file can't be finished by the
                    # new one; gluing it to the new file's first line would
                    # corrupt both.
                    if reader.pending:
                        _warn_drop("incomplete line at input rotation")
                    # Keep the old file until the new one is open: stopped
                    # while waiting for it, the position saved is the old
                    # file's end, and the next start carries on from there.
                    new_f, new_inode = _open_tail(COMBINED_FILE)
                    if new_f is None:
                        break
                    f.close()
                    f, current_inode = new_f, new_inode
                    f.seek(0)
                    reader = _LineReader(f)
                    continue

                out_file, out_inode = _reopen_output_if_rotated(SLOW_LOG_OUTPUT, out_file, out_inode)
                _purge_stale(blocks, block_times, active_block, out_file)
                time.sleep(POLL_INTERVAL)
    finally:
        # In-flight blocks are saved, not flushed: one that's mid-delivery can
        # look gap-free (lines 1..k of N) and would be written truncated. The
        # next start restores them and reads the rest of their lines.
        out_file.close()
        _save_state(f, reader, blocks, block_times, active_block)
        f.close()
    log.info("Daemon stopped")


if __name__ == "__main__":
    run()
