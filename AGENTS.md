# Repository Guidelines

## Project Structure & Module Organization
`grclanker` has two main surfaces:

- `src/`: Astro marketing/docs site (`src/pages`, `src/content/docs`)
- `cli/`: TypeScript CLI runtime, prompts, extensions, scripts, and tests
- `specs/`: product and tool build specs, usually one `*-spec.md` per integration

Most contributor work lands in `cli/extensions/grc-tools/` for native tools, `cli/tests/` for regression coverage, and `cli/scripts/` for sync or live-smoke helpers.

## Build, Test, and Development Commands
- `npm run dev`: run the Astro site locally
- `npm run build`: build the Astro site
- `npm --prefix cli run build`: compile the CLI to `cli/dist/`
- `npm --prefix cli run dev`: run the CLI entrypoint with `tsx`
- `npm --prefix cli run test:cli`: build the CLI and run the full Node test suite
- `npm --prefix cli run sync:fedramp`: refresh generated FedRAMP docs/content from official sources

Live smoke scripts exist for integrations and intentionally skip when creds or external CLIs are missing, for example `npm --prefix cli run test:gws-ops:live`.

## Coding Style & Naming Conventions
Use ESM TypeScript and keep existing style consistent: 2-space indentation, semicolons, descriptive helper names, and small focused functions. New native tools should follow the existing `*_check_access`, `*_assess_*`, and `*_export_*` naming patterns. Keep prompts and site copy concise and grounded in shipped behavior.

## Testing Guidelines
Tests use Node’s built-in runner (`node --test`) with `.test.mjs` files in `cli/tests/`. Add targeted tests for every new tool, plus bundle/output-path checks when exporting files. Prefer mocked API coverage first, then add an optional `test:*:live` script for real-tenant smoke tests when relevant.

## Commit & Pull Request Guidelines
Recent history uses short imperative subjects like `Add Okta compliance assessment tools` and `Add Google Workspace CLI operator bridge`. Keep commits scoped to one feature or hardening pass. PRs should include:

- a clear summary of user-facing changes
- linked Linear issue(s)
- validation commands run
- screenshots only when site/docs UI changed

## Security & Configuration Tips
Never commit tenant credentials, generated evidence bundles, or local workspace artifacts. `.gitignore` already covers common secrets such as `.env*`, `.okta.yaml`, `credentials.json`, `client_secret.json`, `*service-account*.json`, `export/`, and `oscal-workspace/`. Prefer environment variables or local config files outside the repo for sensitive values.
