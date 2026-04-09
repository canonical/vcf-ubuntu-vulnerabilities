# Developer Guide

## Prerequisites

- Python 3.12+ with [uv](https://docs.astral.sh/uv/)
- Node.js 18+

## Setup

```bash
uv sync        # install Python dependencies
npm install    # install Cypress and serve
```

## Python tests

```bash
uv run pytest -v
```

## Generating the dashboard

```bash
uv run python -m scripts.generate
# output: dist/index.html
```

## Cypress e2e tests

The Cypress suite runs against a locally-served copy of `dist/index.html`.
Generate the dashboard first, then run the tests:

```bash
uv run python -m scripts.generate
npm run cy:run
```

`cy:run` starts a static file server on port 8080, waits for it to respond,
runs the Cypress specs headlessly, then shuts the server down.

To run the tests visibly in Chromium:

```bash
npm run cy:open
```

This uses `--headed --no-exit` so the browser stays open after specs complete.
Press Ctrl+C in the terminal to stop the server when done.

> **Note on interactive mode:** The Cypress App (`cypress open`) uses Electron as
> its GUI, which crashes with a GPU sandbox error on this machine. `cy:open`
> bypasses the GUI and runs specs directly in Chromium. Firefox snap cannot be
> used — snap network confinement prevents it from connecting to Cypress's proxy.

> **Note on snap browsers:** Cypress cannot auto-detect snap-installed Firefox
> or Chromium because their `/usr/bin/` entries are shell wrapper scripts.
> `cypress.config.js` registers both explicitly by their real snap binary paths.
> Firefox snap cannot currently be used with Cypress — snap confinement prevents
> the browser from connecting back to the Cypress proxy. Chromium snap works and
> is the default for `cy:open`. Google Chrome (if installed as a deb/binary) also
> works and can be selected with `--browser chrome`.

### Adding tests

Specs live in `cypress/e2e/`. Each file follows the `*.cy.js` naming convention.

When selecting elements from the dashboard, use `data-cy` attributes rather than
CSS classes or generated IDs — the template adds these attributes specifically for
tests so they remain stable across styling and structural refactors:

```js
// preferred
cy.get('[data-cy="generated-date"]')

// avoid — couples the test to generated index suffixes or CSS class names
cy.get('#generated-date-1')
cy.get('.u-text--muted')
```

To expose a new element to tests, add `data-cy="<name>"` in the relevant place
in the `_TEMPLATE` string inside `scripts/generate.py`, then regenerate the
dashboard before running Cypress.
