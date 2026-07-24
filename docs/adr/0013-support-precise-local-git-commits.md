# ADR 0013: Precise local Git commits

Status: Accepted

ShellBridge supports local status, explicit staging and unstaging, and exact commits for repositories beneath the configured operation root. Remote Git, branch/tag changes, merge, rebase, history rewrite, reset, clean, amend, and submodules remain unsupported.

A commit proposal freezes the canonical repository, branch, HEAD, index, worktree state, target tree, message, and complete file list. Execution rejects any relevant state change. The Git subprocess disables hooks, signing, editors, pagers, external diffs, text conversion, network prompts, and unsafe configuration.

Blocked resources and trust-root content cannot enter a commit. Unborn `HEAD` is supported through an exact root-commit flow described in `docs/git-unborn-head-support.md`.
