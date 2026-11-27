"""Write one snapshot of this PC's TCP connections for network.windows (design network-windows-v1 §1.1, §8.2).

    python data/scripts/snapshot_connections.py

Reads the TCP connection table once (standard library `ctypes`, GetExtendedTcpTable) and
writes one JSON-lines file under the ignored folder var/network-snapshots/, which
`import_network_windows.py --snapshots` reads later. Rows hold addresses, ports, the owning
process id and the process file name (never its path): keep these files private.

Read-only: it never kills, blocks, resets or connects anything, never changes a setting and
never creates a scheduled task. Run it by hand, or create your own scheduled task; ETIS never
does. Reading other users' process names may need administrator rights; without them the
file name is left empty. When run as a script, socket connections are blocked in this process.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))

from app.engines.network_windows import snapshots  # noqa: E402

OUT_DIR = ROOT / 'var' / 'network-snapshots'
EXIT_OK, EXIT_FAILED = 0, 2


def block_network() -> None:
    """Process-wide: no socket may connect while the command runs."""
    import socket

    def blocked(*args, **kwargs):
        raise OSError('network_blocked_in_snapshot_connections')
    for name in ('connect', 'connect_ex', 'sendto'):
        setattr(socket.socket, name, blocked)
    socket.create_connection = blocked
    socket.getaddrinfo = blocked


def main(argv=None, *, out_dir: Path = OUT_DIR, table=None, image=None, now=None, out=sys.stdout) -> int:
    argparse.ArgumentParser(description=__doc__.split('\n\n')[0]).parse_args(argv)
    now = now or (lambda: datetime.now(timezone.utc))
    kwargs = {k: v for k, v in (('table', table), ('image', image)) if v is not None}
    try:
        rows = snapshots.snapshot_rows(now=now, **kwargs)
    except snapshots.SnapshotError as exc:
        print(f'snapshot failed: {exc}', file=out)
        return EXIT_FAILED
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f'snapshot-{now().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")}.jsonl'
    with target.open('x', encoding='utf-8', newline='\n') as handle:   # never overwrites
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + '\n')
    print(f'snapshot written: {len(rows)} connections to var/network-snapshots/{target.name}', file=out)
    return EXIT_OK


if __name__ == '__main__':
    block_network()
    raise SystemExit(main())
