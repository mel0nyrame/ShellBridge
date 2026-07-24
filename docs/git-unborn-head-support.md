# Git Unborn HEAD Support

## Overview

ShellBridge supports Git repositories that have been initialized but do not yet contain a commit. Git calls this an **unborn branch**: `HEAD` names a branch, but that branch does not yet resolve to a commit.

A typical repository in this state is created with:

```bash
git init -b main
echo hello > README.md
```

Native Git can inspect, stage, unstage, and create the first commit in this state. ShellBridge preserves those capabilities without weakening its repository-boundary checks, immutable proposal model, or execution-time race detection.

## Public behavior

### Repository status

`get_git_status` reports an unborn repository normally instead of treating the missing commit as repository corruption.

Representative response:

```json
{
  "branch": "main",
  "head": null,
  "unborn": true,
  "staged": [],
  "unstaged": [],
  "untracked": ["README.md"]
}
```

The service distinguishes an unborn branch from:

- a detached `HEAD`;
- a branch reference that points to a missing object;
- a damaged or incomplete Git repository;
- a non-repository directory;
- a path rejected by ShellBridge policy.

### Stage and unstage

`git_stage` can add explicit paths or all changes to an unborn repository. The index does not require an existing commit, so staging follows the same path and safety rules used for repositories with history.

`git_unstage` compares the index against Git's empty tree when no commit exists. This removes selected entries from the index while preserving the corresponding worktree files as untracked files.

### First commit

`prepare_git_commit` can prepare the initial root commit. The proposal records:

- canonical repository path;
- branch name;
- whether the branch is unborn;
- current `HEAD`, which is `null` for the first commit;
- initial index tree and index fingerprint;
- selected worktree state;
- target tree;
- exact file list;
- exact commit message.

`execute_proposal` creates a root commit with no parent when the frozen proposal still matches the repository. Later commits continue to include the existing `HEAD` as their parent.

## Comparison baseline

Operations that normally compare against `HEAD` use Git's empty tree while the branch is unborn. The empty tree is obtained through Git plumbing rather than by creating a synthetic or temporary commit.

This provides a consistent baseline for:

- worktree and index diffs;
- target commit planning;
- staged file lists;
- diff statistics;
- repository-state fingerprints.

## Safety properties

Supporting an unborn branch does not relax ShellBridge's existing protections.

### Repository boundaries

The repository must still:

- be inside the configured operation root;
- resolve to a real Git worktree;
- pass canonical-path checks;
- not be supplied through a symbolic-link alias;
- satisfy Git's ownership protections.

ShellBridge does not globally disable `safe.directory` and does not trust arbitrary paths merely because they are under `/root`.

### Immutable proposals

A prepared first-commit proposal cannot silently become a normal later commit. Execution is rejected when another process creates the first commit after preparation.

Execution is also rejected when any frozen input changes, including:

- branch or `HEAD` state;
- index contents;
- selected worktree contents;
- target tree;
- selected file list.

The execution endpoint accepts only the proposal identifier. Callers cannot override the repository, files, branch, command, working directory, or commit message during execution.

### Empty commits

An empty unborn repository can be inspected, but ShellBridge refuses to prepare an empty first commit. This keeps the Git transaction tool focused on committing actual selected changes.

### Detached HEAD

Status inspection remains available for a detached `HEAD`, but commit preparation is rejected. ShellBridge's commit workflow updates a named branch reference and therefore requires an attached branch.

## Commit construction

The target tree is generated in a temporary index. The live index and repository references are changed only after proposal validation succeeds.

For an unborn branch, the commit is created without a parent. For a repository with history, the existing commit is supplied as the parent. The branch reference is updated with an expected old value so concurrent changes cause the operation to fail rather than overwrite another writer's work.

After execution, ShellBridge verifies that:

- the branch points to the new commit;
- the new commit contains the frozen target tree;
- the reported file list includes root-commit additions correctly;
- the repository status reflects the completed transaction.

## Test coverage

`test/git.test.ts` covers the principal behavior and security boundaries:

1. reporting an unborn branch and untracked files;
2. rejecting a branch reference that points to a missing object;
3. staging and unstaging without changing worktree files;
4. creating and verifying an immutable root commit;
5. rejecting a proposal after an external first commit;
6. staging and unstaging all files;
7. rejecting execution after index changes;
8. preserving the normal commit flow in repositories with history;
9. reporting an empty unborn repository and refusing an empty commit;
10. rejecting execution after selected worktree content changes;
11. allowing detached-HEAD status while rejecting commit preparation;
12. rejecting non-repositories, symbolic-link paths, and paths outside the operation root;
13. preserving Git dubious-ownership protection.

## Non-goals

This support does not:

- create an automatic placeholder or empty commit;
- contact a remote repository;
- bypass repository ownership checks;
- expose arbitrary Git command execution;
- permit callers to mutate a prepared proposal;
- broaden ShellBridge's filesystem operation root.
