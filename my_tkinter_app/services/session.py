"""
session.py
==========

A workspace for one run of the application, deleted when it exits.

WHAT IS TEMPORARY AND WHAT IS NOT

  temporary  everything derived from the capture the user opened: the flow
             CSV, flow_extraction.json, the case record, the panels' saved
             output and the investigator's review. All of it lives under a
             single directory created at start-up and removed at exit.

  permanent  the knowledge base, the cited source PDFs, their extraction
             cache, and the trained model bundle. Those are the tool's own
             resources, not the user's data -- they are the same for every
             case, they are what makes a citation checkable, and rebuilding
             the source cache costs about 30 seconds.

  untouched  the capture itself. It is opened where the user put it and
             never copied, so there is nothing of theirs to delete. Deleting
             a file the user chose would be destroying evidence.

WHY A PID AND A TIMESTAMP IN THE NAME
Two instances must not share a workspace, and a crashed instance must not
leave a directory that the next run mistakes for its own. The name carries
both, and cleanup only ever removes a directory this process created.

CLEANUP RUNS TWICE ON PURPOSE
`atexit` covers a normal exit and most crashes. The window close handler
covers the case where Tk tears down first. Both call the same function and
it is safe to call repeatedly.
"""
import os
import shutil
import atexit
import tempfile
from datetime import datetime

PREFIX = "forenxai_session_"

# Created once, at import, so every module that asks for a path gets the
# same workspace without having to pass it around.
SESSION_DIR = os.path.join(
    tempfile.gettempdir(),
    f"{PREFIX}{os.getpid()}_{datetime.now():%Y%m%d_%H%M%S}",
)

os.makedirs(SESSION_DIR, exist_ok=True)

_cleaned = False


def cleanup():
    """Remove this run's workspace. Safe to call more than once.

    Refuses to delete anything that is not the directory this process
    created -- the guard is cheap and the failure it prevents is deleting
    a user's own folder because a path was wrong.
    """
    global _cleaned
    if _cleaned:
        return
    _cleaned = True

    base = os.path.basename(SESSION_DIR)
    inside_temp = os.path.abspath(SESSION_DIR).startswith(
        os.path.abspath(tempfile.gettempdir()))

    if not (base.startswith(PREFIX) and inside_temp):
        return

    shutil.rmtree(SESSION_DIR, ignore_errors=True)


def sweep_orphans(older_than_hours=24):
    """Remove workspaces left behind by earlier runs that did not exit.

    A crash hard enough to skip both cleanup paths leaves a directory with
    a capture's flow table in it. Nothing else will ever remove it, so the
    next run does -- but only ones old enough that they cannot belong to
    another instance running right now.
    """
    root = tempfile.gettempdir()
    cutoff = older_than_hours * 3600
    now = datetime.now().timestamp()

    for name in os.listdir(root):
        if not name.startswith(PREFIX) or name == os.path.basename(SESSION_DIR):
            continue
        path = os.path.join(root, name)
        try:
            if os.path.isdir(path) and now - os.path.getmtime(path) > cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


atexit.register(cleanup)
