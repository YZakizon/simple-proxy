# Repository Agent Instructions

## Pull request completion

- After creating or updating a pull request, keep monitoring its current head
  until the Codex reviewer posts a verdict.
- Treat review feedback marked as a blocker as actionable. Fix every blocker,
  rerun the relevant validation, commit, push, and continue monitoring.
- Merge only when required CI checks pass and the Codex reviewer posts `LGTM`
  for the pull request's current head.
- A new commit invalidates an earlier `LGTM`; wait for a fresh verdict on the
  new head before merging.
