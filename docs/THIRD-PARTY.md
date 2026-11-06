# Third-party code

[Back to the README](../README.md)

What `jb` ships that it did not write, and how each piece was checked. Versions are pinned; none was less than two weeks old when pinned.

## Vendored in the binary (the dashboard)

| File | Version | Licence | Source and check |
|---|---|---|---|
| `internal/adapters/web/static/d3.min.js` | d3 7.9.0 | ISC (`d3.LICENSE.txt`) | The npm tarball `d3-7.9.0.tgz`; its SHA-512 matched the registry's `dist.integrity`. The extracted `dist/d3.min.js` is unmodified; its SHA-256 is pinned in `TestVendoredLibrariesArePinned`. |
| `internal/adapters/web/static/htmx.min.js` | htmx.org 2.0.11 | 0BSD (`htmx.LICENSE.txt`) | The npm tarball `htmx.org-2.0.11.tgz`, integrity checked the same way; unmodified; SHA-256 pinned in the same test. |

`static/estate.js` and `static/sheet.js` are this project's own and are not third-party.

## Go modules added for the dashboard

| Module | Used by | Licence |
|---|---|---|
| `github.com/a-h/templ` | `internal/adapters/web` (the generated components call its runtime) | MIT |
| `github.com/dominikbraun/graph` | `internal/estategraph` only (topology and connected components) | MIT |

A program that imports only the `jb` or `sdk` packages does not link either of them.

## Build tools (not shipped)

The templ CLI (`v0.3.1020`, matching the runtime library) and the Tailwind standalone CLI (`v4.3.3`) generate files that are committed. `make ui` installs templ with `go install` at the pinned version and downloads Tailwind from its GitHub release, refusing the file unless its SHA-256 matches the one in the `Makefile`.
