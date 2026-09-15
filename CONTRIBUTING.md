# Development workflow

External contributions are not accepted until the project has selected a license. This document defines the workflow used for project-owned changes in the meantime.

Before implementation, describe the outcome, non-goals, affected modules, and proof required. Wire-sensitive changes must include a deterministic local test or capture fixture. Live services may supplement local evidence but must not be the only proof.

Pull requests should avoid unrelated formatting, renaming, dependency updates, or abstraction. A public option must affect an observable result and have a test.

Run the checks documented in the root `AGENTS.md` before requesting review.
