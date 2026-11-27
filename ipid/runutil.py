"""Small helpers shared by the long-running scripts (scan.py, lifetime.py)."""
import os
from datetime import datetime, timezone
from pathlib import Path


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stop_on_signal(signum, frame):
    raise KeyboardInterrupt


def safe_print(*a, **kw):
    """print() that survives a closed terminal (e.g. after SSH dropped)."""
    try:
        print(*a, **kw)
    except OSError:
        pass


def chown_to_sudo_user(*paths):
    """Give files created under sudo back to the user who ran sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid:
        return
    uid, gid = int(uid), int(gid)
    for top in paths:
        top = Path(top)
        if not top.exists():
            continue
        os.chown(top, uid, gid)
        for dirpath, dirnames, filenames in os.walk(top):
            for name in dirnames + filenames:
                os.chown(os.path.join(dirpath, name), uid, gid)
