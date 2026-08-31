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

## Codex pull request reviews

- Review the pull request's current live head before issuing a verdict.
- Post one concise top-level verdict beginning with either `Blocker` or `LGTM`.
- End every verdict comment with the footer `Codex Reviewer Agent`.

## Production deployment safety

- Treat `do not deploy`, `do not restart`, and equivalent instructions as an
  absolute stop on production mutations. A later ambiguous phrase does not
  override the stop; ask the user to clarify before taking action.
- Building or pushing an image, including pushing to a registry, does not
  authorize deploying that image or changing a production node.
- Do not edit production files, recreate containers, restart services, change
  runtime configuration, or run deployment commands without separate, explicit,
  and unambiguous authorization for the named production target.
- Prepare repository changes on a scoped branch and pull request. Do not deploy
  them until required CI passes and the Codex reviewer posts `LGTM` for the
  current pull request head, followed by explicit deployment authorization.
- If instructions conflict about a production action, stop after safe read-only
  inspection, report the conflict, and ask for direction. Never resolve the
  conflict by assuming permission to mutate production.
- Before an authorized production change, state the exact target, image or
  commit, files or services affected, and whether a restart or recreation will
  occur. Keep unrelated services and host configuration untouched.
