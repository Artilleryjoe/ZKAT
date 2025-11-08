"""Git anchoring helpers for Milestone 1 attestations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from git import Repo
from git.exc import GitCommandError


def commit_attestation(
    repo_path: str | Path,
    file_path: str | Path,
    message: str,
    *,
    remote: str | None = "origin",
    branch: str | None = "main",
) -> dict[str, Any]:
    """Commit the attestation artifact to a Git repository.

    The helper stages ``file_path`` (relative to ``repo_path``), creates a new
    commit, and optionally attempts to update the provided ``branch`` reference
    to point at the commit.  Pushing to a remote is deliberately out of scope
    because the execution environment typically has no network access.
    """

    repo_path = Path(repo_path)
    file_path = Path(file_path)
    repo = Repo(repo_path)

    if file_path.is_absolute():
        tracked_path = file_path
    else:
        tracked_path = repo_path / file_path

    repo.index.add([str(tracked_path)])
    commit = repo.index.commit(message)

    update_result: str | None = None
    if branch is not None:
        try:
            ref = repo.references[branch]
            ref.set_object(commit)
            update_result = f"updated {branch}"
        except (IndexError, GitCommandError, AttributeError, KeyError):
            update_result = None

    return {
        "commit": commit.hexsha,
        "tree": commit.tree.hexsha,
        "update": update_result,
        "remote": remote,
        "path": str(tracked_path.relative_to(repo_path)),
    }


__all__ = [
    "commit_attestation",
]
