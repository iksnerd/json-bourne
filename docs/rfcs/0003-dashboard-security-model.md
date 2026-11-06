# RFC 0003: Dashboard security model
Status: implemented
Scope: the security rules of the `jb serve` dashboard (`internal/adapters/web`), the reasons for them and the test that holds each one.
Accepted: 2026-11-06 by the maintainer

This is a back-fill RFC. The dashboard was built before the RFC process existed. This document records the rules that ship and the reasons for them. It changes no behaviour. Where a rule has no test, the Conformance section says so.

## Summary

`jb serve` shows the runs, findings, reputation snapshots, watch log and estate map of one case in a browser. It reads attacker-controlled text: paths, user agents and host names that came out of real log lines. The dashboard therefore treats every stored string as hostile.

The model has seven parts:

1. The dashboard is read-only and answers GET and HEAD only.
2. It binds loopback by default and refuses a request whose `Host` header is not a loopback name.
3. A strict Content-Security-Policy allows script, style, image and fetch from this origin only.
4. Scripts are two vendored libraries, pinned by hash, and two files of this project.
5. Stored text reaches the page only through templ escaping. A test bans the raw-HTML escape hatches.
6. Links are built from fixed paths and percent-encoded values.
7. Every query and every response is bounded.

There is no authentication. `--allow-remote` is the operator's explicit decision to accept that.

## Motivation

A dashboard that shows log data is a stored-XSS target. The text that an attacker puts into a request path appears on a page that the defender opens. If that text runs as script, the attacker controls the defender's browser while it holds an open view of the evidence.

Three concrete cases drove the design:

- **A hostile user agent.** A request carries `<script>` in its `User-Agent`. The page renders the string. It must show as text.
- **A rebinding page.** The operator has `jb serve` on loopback. A page in the same browser, from a hostile site, tries to read it through DNS rebinding. The server must refuse the foreign `Host` name.
- **A forgotten route that writes.** Any route that changes state could be reached by a cross-site request. The dashboard has none.

v0.3.0 rebuilt the dashboard with htmx and d3 for an interactive estate graph. That needed script, so the policy changed (see Compatibility). This RFC records the model that results.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

## How this design was made

**Escape in the template, not by filtering.** Stored strings go through templ components. templ escapes each `{ value }` for the place it lands in (text, attribute, URL). The alternative was to strip dangerous characters from stored text. A filter has to know every context, and one miss is a hole. A first pass replaces control characters and caps length at 300 characters. That pass is hygiene. It does not do the escaping.

**Ban the escape hatches in a test.** templ and `html/template` have functions that mark text as safe. One use would bypass escaping for everything it touches. `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch` fails the build on any of them. The alternative was a review rule, which a tired reviewer can miss.

**A CSP that denies by default.** The policy starts from `default-src 'none'` and allows only what the pages use. The alternative was to rely on escaping alone. The CSP is a second layer: if an escape is ever missed, an injected inline script still does not run.

**Allow `script-src 'self'`, not a hash list.** The estate graph needs d3. A source list of `'self'` was the smallest change from the earlier "no script" policy. A hash list would be stricter. See Security considerations for what it would add.

**Vendor and pin the libraries.** The pages load no remote script. d3 and htmx are copies of the npm release files, embedded in the binary, and a test pins their SHA-256. The alternative was a CDN, which would let a third party run script in the dashboard and would break offline use.

**Configure htmx not to evaluate text.** htmx can run code found in attributes and in swapped fragments. The page turns that off in `htmxConfig`. Each key is described below.

**Loopback by default, a Host check on top.** Binding to loopback keeps other machines out. It does not stop a page in the operator's own browser, so the Host header check stops DNS rebinding. The alternative was a token. A token adds state and a login step to a tool used during an incident. The choice is to document the lack of authentication instead (see Security considerations).

**Open the store per request.** The handle is opened for each request and closed when the request ends. This keeps `jb watch`, the one writer, from being locked out between requests. It also means no long-lived handle exists to misuse.

## The design

### Transport and access

- **Methods.** The server MUST answer GET and HEAD only. Any other method MUST get 405 with `Allow: GET, HEAD`. Held by `TestOnlyReadMethods` and, for the favicon route, `TestFaviconIsNoContentWithTheSecurityHeaders`.
- **Read-only storage.** The dashboard MUST read the store through a handle opened with `access_mode=READ_ONLY`. The `DashboardStore` port has no write method. Held by `TestDashboardHandleIsReadOnly` in `internal/adapters/duckdb/dashboard_test.go`. The web package imports neither `database/sql` nor `os`, held by the dependency rule for `internal/adapters/web` in `internal/archtest/archtest_test.go`.
- **No SQL endpoint.** No route MAY accept SQL. No test asserts the absence of such a route. The routes are the fixed list in `New` in `web.go`. See Conformance.
- **Bind.** `CheckAddr` MUST return an error wrapping `ErrNotLoopback` for a non-loopback address unless remote binding is allowed (`--allow-remote` on the CLI). A malformed address wraps `ErrBadAddr`. Neither message names a command-line flag, so a Go caller can show it as is. `":8090"`, `"0.0.0.0:8090"` and `"[::]:8090"` count as non-loopback. `localhost` MUST become `127.0.0.1`, so a name lookup does not decide where the server binds. Held by `TestCheckAddr`, and for the flag and its hint by the tests in `cmd/jb/serve_test.go` (`TestServeAllowRemoteWarnsLoudly` and `TestServeRequiresASourceAndRefusesNonLoopback`).
- **Host header.** When the server is bound to loopback, a request whose `Host` is not `localhost`, a loopback IP or a loopback IPv6 address MUST get 421. When `Loopback` is false, the server MUST NOT filter on `Host`. Held by `TestForeignHostHeaderRefusedOnLoopbackOnly`.
- **Hosts behind a proxy.** `Options.AllowedHosts` is a list of at most 16 values, each a host name, an IP address or a bracketed IPv6 address with an optional `:port`. When it is not empty, it replaces the loopback rule: the `Host` header MUST equal one of the values, compared exactly and without regard to ASCII case, or the request gets 421. This holds whether `Loopback` is true or false, so a handler behind a reverse proxy that rewrites `Host` keeps a Host check. A value with no port matches only a header with no port. There are no wildcards. An empty value, a wildcard, a scheme, a path, a bad port or a list over 16 is refused: `Options.Validate` returns an error wrapping `ErrBadAllowedHosts`, and `New` panics on such options. An empty list keeps the rules above exactly. The method check, the security headers, the CSP and the read-only store are unchanged. The list is not authentication: the proxy MUST authenticate, and MUST NOT forward a `Host` the visitor chose. Held by `TestAllowedHostsReplacesTheLoopbackRule`, `TestEmptyAllowedHostsKeepsTodaysBehaviour`, `TestAllowedHostsRefusedAtConstruction` and `TestAllowedHostsKeepsHeadersAndReadOnly`.
- **Order of checks.** The method check runs first, then the Host check. Both run before routing, so every route is covered, including `/static/` and `/favicon.ico`. Held in part by the two tests above. No test asserts the order.
- **Server limits.** `NewServer` MUST set read-header, read, write and idle timeouts and a header size of at most 64 KiB. The code sets 5 s, 15 s, 30 s, 60 s and 16 KiB. Held by `TestServerHasTimeouts`, which asserts only that each is set and that the header size is at most 64 KiB.
- **Per-request budget.** Each request has a 20 second budget (`http.TimeoutHandler`), which also cancels the query context. No test asserts the budget.
- **Per-request store handle.** The handle MUST be closed when the request ends. Held by the `f.closed` check in `TestRunPageShowsSummaryFindingsAndSampleAndPassesConfiguredFields` (`web_test.go`, near line 392), which covers the run page only.
- **Serving only.** The web package MUST NOT call out: no `net/http` client symbol and no `net.Dial`. Held by `TestWebAdapterIsServingOnly`, with `TestServingScannerFlagsClientSymbols` checking the scanner.

### Response headers

Every response from the handler sets these headers before any other check:

| Header | Value as served |
|---|---|
| `Content-Security-Policy` | the policy below |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

The Content-Security-Policy, copied from the constant `csp` in `internal/adapters/web/web.go`:

```
default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

- **CSP present.** Every response, including errors, the favicon and static files, MUST carry the policy, and the policy MUST contain `default-src 'none'`, `script-src 'self'`, `connect-src 'self'`, `style-src 'self'`, `img-src 'self'`, `base-uri 'none'`, `form-action 'self'` and `frame-ancestors 'none'`. Held by `TestEveryPageSetsSecurityHeadersAndNoCORS`.
- **CSP excludes unsafe sources.** The policy MUST NOT contain `unsafe-inline`, `unsafe-eval`, `http`, `data:`, `*`, `blob:` or `strict-dynamic`. Held by the same test. The test checks for these substrings. It does not compare the whole string, so a new directive would pass.
- **`nosniff`.** Every response MUST carry `X-Content-Type-Options: nosniff`. Held by the same test, and for the JSON endpoint by `TestEstateGraphJSON`.
- **No CORS.** No response MAY carry an `Access-Control-*` header. Held by `TestEveryPageSetsSecurityHeadersAndNoCORS` and `TestOnlyReadMethods`.
- **The other three headers.** `Referrer-Policy`, `Cache-Control` and `Cross-Origin-Resource-Policy` are set in `New`. No test asserts them. See Conformance.

### Scripts

- **Only own-origin scripts.** A page MAY load `/static/htmx.min.js`, `/static/d3.min.js`, `/static/estate.js` and `/static/sheet.js`, each as `<script src="..." defer></script>`, and nothing else. Held by `TestPagesCarryOnlyTheVendoredScriptsAndNoInlineCode`. The test also fails on an inline script body, an inline event handler, an inline `style=` attribute, a `javascript:` URL, an `@import` and an external `src`, `href` or `action`.
- **Which page loads what.** htmx loads on every page. d3, `sheet.js` and `estate.js` load on the estate page only. Held by the same test for d3 and `sheet.js`, and by `TestEstatePageHasTheSheetThatHTMXFills` for the order.
- **Vendored and pinned.** `static/d3.min.js` (d3 7.9.0) and `static/htmx.min.js` (htmx.org 2.0.11) MUST match the SHA-256 pinned in `TestVendoredLibrariesArePinned` in `internal/adapters/web/web_ui_test.go`. The test also checks that each ships with its licence file and that `d3.min.js` starts with its version comment. Provenance, licence and the verification of the npm tarball are in [docs/THIRD-PARTY.md](../THIRD-PARTY.md). A change to either file MUST change the pin in the same commit.
- **Own files are not pinned.** `static/estate.js` and `static/sheet.js` are this project's code. No hash pins them. Review is the control.
- **Named static files only.** `/static/` MUST serve only the files in the `staticFiles` map in `web.go`, with no directory listing and no traversal. Held by `TestStaticServesOnlyTheNamedFiles`.

### htmx configuration

`htmxConfig` in `ui.go` is written into a `<meta name="htmx-config">` so the page needs no inline script. Each key closes one path:

| Key | Value | What it closes |
|---|---|---|
| `allowEval` | `false` | htmx will not evaluate text as code (`hx-on` and `js:` triggers). |
| `allowScriptTags` | `false` | A `<script>` in a swapped fragment does not run. |
| `includeIndicatorStyles` | `false` | htmx injects no `<style>` element, which the CSP would refuse anyway. |
| `historyEnabled` | `false` | htmx keeps no snapshot of a page of log text in the browser's storage. |
| `refreshOnHistoryMiss` | `false` | A history miss does not reload the page through htmx. |
| `selfRequestsOnly` | `true` | htmx sends requests to this origin only. |

The meta element MUST carry these values. Held by `TestHTMXIsConfiguredNotToEvaluateTextRunScriptsOrKeepPages`. The markup MUST NOT contain `hx-post`, `hx-put`, `hx-patch`, `hx-delete`, a non-GET form method, `hx-on`, `hx-vals` or `hx-headers`. Held by `TestNothingInTheMarkupCanChangeState`.

### Escaping

- **Escape hatches banned.** The non-test sources of `internal/adapters/web` (`.go` and `.templ`) MUST NOT contain `templ.Raw`, `templ.SafeURL`, `templ.ComponentScript`, `templ.JSFuncCall`, `templ.JSONScript`, `templ.Script`, `templ.SafeScript`, `templ.SafeCSS`, `template.HTML`, `template.JS`, `template.URL`, `unsafe.` or `@templ.`. Held by `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch`. The test skips comment lines, generated `_templ.go` files and `_test.go` files, and it fails if it scans fewer than six sources.
- **Hostile text shows as text.** A stored string with `<script`, an `onmouseover=` attribute or `javascript:` MUST NOT appear raw on any page. Held by `TestHostileStoredTextIsEscapedOnEveryPage`, which also fails if fewer than five pages show the escaped form, so the payload must reach the templates. `TestHTMXAsksGetFragmentsAndEveryPageVariesOnIt` runs the same check on htmx fragments.
- **Length cap.** One stored string MUST be cut to 300 characters (`textCap`, `clip` in `views.go`), with control characters replaced. Held by `TestLongStoredStringsAreCapped`.
- **Filter echo.** The findings filter echoes the user's query. It MUST be escaped and bounded. Held by `TestFindingsFilterEchoIsEscapedAndBounded`.
- **Static files are not text from the evidence.** `estate.js` sets labels with d3's `.text()` and `textContent`. No test scans the static JavaScript for `innerHTML`. The archtest rule scans `.go` and `.templ` files only. See Conformance.

### Links

- **Fixed paths and encoded values.** A link MUST be a relative path built in `ui.go` (`runHref`, `nodeHref`, `edgeHref`, `graphHref`) from a fixed prefix and values passed through `escQuery`. `escQuery` percent-encodes everything except `A-Z a-z 0-9 - . _ ~`. A stored string MUST NOT become a whole link. Held by `TestEscQuery` for the encoder. `TestEstateGraphJSON` checks that node and edge links start with the built prefixes. The templ sources contain no `SafeURL`, which the archtest rule enforces.
- **Panel links only where a panel exists.** Held by `TestPanelLinksOnlyWhereThereIsAPanel`. This is about behaviour, not security, and is listed because the htmx links must not appear on a full page.

### The JSON endpoint

`GET /estate/graph.json?g=<id>` returns the estate graph for the interactive drawing.

- **Escaped.** It is encoded with Go's `encoding/json`, which writes `<`, `>` and `&` as `<`, `>` and `&`. Held by `TestEstateGraphJSON`, which checks that a hostile label appears as `<script>` and never as `<script`.
- **Typed.** The content type is `application/json; charset=utf-8`, and `nosniff` is set, so a browser does not run it as script. Held by `TestEstateGraphJSON`.
- **Bounded.** The endpoint returns at most 300 nodes (`graphJSONNodes`) and sets `cut: true` when it drops some. Held by `TestEstateGraphJSONIsBounded`.
- **Built links.** Each node and edge carries an `href` built by `nodeHref` or `edgeHref`, never taken from the stored file. Held by `TestEstateGraphJSON`.
- **Unknown map.** An unknown `g` MUST get 404. Held by `TestEstateGraphJSON`.

### Bounds

Every query is bounded by a row limit. The limits in `web.go` are: runs 100, top lists 15, raw events 50, findings 200, reputation 200, log tail 100 lines, 200 estate rows per table and 40 nodes in the static drawing.

- **Query limits.** Every store query MUST pass a limit of at most 500, and the raw-events panel at most 100. Held by `TestEveryQueryIsBounded`. The test covers the overview, run, findings and reputation pages.
- **Rendered rows.** A table MUST NOT render more rows than its cap, and a cut table MUST say so. Held by `TestRowsRenderedNeverExceedTheCap`.
- **Failure is visible.** A failed query MUST show an error banner, never an empty table. Held by `TestUnknownRunIs404AndStoreErrorsAreNot` and `TestEmptyAndFailedPanelsSayWhy`.

## Non-goals

- **Authentication.** There is no login, token or session. The defences are the loopback bind and the Host check.
- **TLS.** The server speaks plain HTTP. An operator who exposes it remotely adds a front end of their own.
- **Write endpoints.** The dashboard never changes the store, the case or the config.
- **Plugin-supplied pages.** ADR 0001 point 5 keeps the dashboard built in and lets no plugin add a page.
- **Protection against local users.** Another user on the same machine can connect to a loopback port. The model does not defend against that.
- **A browser support matrix.** The CSP and htmx behaviour are checked in Go tests with no browser.

## Drawbacks

- **No authentication means no remote use that is safe.** `--allow-remote` is the only way to listen on another interface, and it gives every host that can reach the port a full view of the evidence.
- **A wider script policy.** The policy moved from no script to `script-src 'self'`. The page now has a script surface that did not exist before v0.3.0.
- **Several controls rest on tests of substrings.** The CSP test checks that substrings are present or absent. It does not compare the whole string.
- **A browser runs none of these tests.** The tests render pages in Go and inspect the text. They show the markup is safe by their own rules. They do not show how a given browser treats the CSP.
- **Vendored files need manual updates.** An update means verifying the npm tarball, replacing the file and licence, and changing the pin in one commit. A security fix upstream needs that work from the maintainer.
- **Generated files are committed.** The `_templ.go` files and `static/tailwind.css` are committed, and `make ui-check` guards staleness. A reviewer reads the `.templ` sources, not the generated code.

## Alternatives and prior art

**No script at all.** The earlier policy, `default-src 'none'`, allowed no script. It was the strongest option and it ruled out an interactive graph and htmx partial updates. The static drawing in `<figure class="static-graph">` still works without script.

**A nonce or hash in the CSP.** A per-response nonce suits inline script. This dashboard has none. A hash list would pin the four files by content. See Security considerations.

**A token in the URL.** A secret in the URL adds state, shows up in browser history and complicates a quick start. It was not chosen.

**Prior art.** The headers used here (`Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Resource-Policy`) are standard web platform headers. This RFC cites no external source for the design, and none was consulted for this back-fill.

## Compatibility

v0.3.0 changed the policy. Before it, the Content-Security-Policy was `default-src 'none'` and no page ran script. CHANGELOG.md, section `[0.3.0]`, records the change: the policy became `script-src 'self'; connect-src 'self'; form-action 'self'`, with the vendored, hash-pinned htmx and d3 and two small files of this project. The same entry states that there is still no inline script, no eval and no other origin, and that the dashboard stays GET-only and read-only.

The same release added `GET /favicon.ico` (204 with the security headers) and rebuilt the Estate page around an interactive d3 graph. The changelog does not name `/estate/graph.json`, the JSON endpoint that feeds it.

The dashboard is not an API. Its HTML, its fragments and its JSON are not a stable contract for other programs. The security rules above are the contract. A change that weakens one MUST go through an RFC (see [docs/rfcs/README.md](README.md), "When you need one").

A change that tightens the policy is allowed without an RFC if the tests still pass, but it SHOULD update this document.

## Security considerations

**What an attacker can do.** The attacker controls the text in the evidence: request paths, user agents, host names, referers and the fields of estate files. The attacker may also be a page in the operator's browser that talks to the loopback port.

**What the design assumes.** The operator runs `jb serve` on a machine whose other local users are trusted. The operator's browser enforces the CSP and the same-origin rules. The npm release files of d3 and htmx are what the pins say they are.

**What it guarantees**, within the tests above. Stored text appears as text. No inline script, handler, style or external reference is present in the pages. Requests that change state are refused. A foreign `Host` is refused on loopback.

**Residual risks.**

- **`script-src 'self'` is wider than the old `'none'`.** The CSP now allows any script served from this origin. The origin serves four named script files, the JSON endpoint and HTML. An attacker who could inject a `<script src>` tag could load any of the four. The JSON endpoint is served as `application/json` with `nosniff`, so a browser refuses it as script. The risk depends on the escaping holding, which the archtest rule and the hostile-text test guard.
- **A hash-based `script-src` would add a binding to content.** A policy of `script-src 'sha256-...'` per file would make the browser refuse a file whose bytes differ, even if the origin served it. That would protect against a tampered embedded file and against an injected tag that points to a different same-origin file. The cost is that the hash list must change with each file edit, and `estate.js` and `sheet.js` change often. This RFC does not adopt it. The vendored libraries are pinned by a test at build time. The browser does not check that pin.
- **Own scripts are unpinned.** `estate.js` and `sheet.js` have no hash pin and no test that bans `innerHTML` or similar sinks. Today they use `.text()` and `textContent` for stored text. A later edit could break that without a test failing.
- **The favicon route.** `GET /favicon.ico` answers 204 with no body. It sits behind the method and Host checks and carries the security headers (`TestFaviconIsNoContentWithTheSecurityHeaders`). It is one more route to keep inside the model. It reads no data.
- **No authentication.** Anyone who can open a connection to the port can read the evidence the dashboard shows. On loopback that means any local user and any local process. With `--allow-remote`, `CheckAddr` allows a non-loopback address, the Host filter turns off, and `jb serve` prints a loud warning (`TestServeAllowRemoteWarnsLoudly`). The operator is then responsible for network controls. The evidence can hold personal data.
- **DNS rebinding in remote mode.** With `--allow-remote` the Host check is off by design, so the rebinding defence is off too. A library caller who knows the names the dashboard is served under sets `Options.AllowedHosts` and gets the defence back (see Hosts behind a proxy).
- **Resource use.** Bounds limit one request. They do not limit the number of requests. A local process can send many. Each opens the store read-only for its length.
- **Static files stay readable.** The static files are not secret. They are the same bytes as the repository.

## Conformance

The tests that hold the rules are named in the design section. In summary:

- **`internal/adapters/web/web_test.go`:** security headers and no CORS, read methods, Host header, hostile text on every page, vendored scripts and no inline code, caps, bounded queries, rows, static files, address checks, server timeouts.
- **`internal/adapters/web/web_ui_test.go`:** htmx configuration, GET-only markup, the JSON endpoint and its bound, the vendored hash pins, `escQuery`, the favicon.
- **`internal/archtest/archtest_test.go`:** `TestWebAdapterHasNoRawHTMLOrScriptEscapeHatch`, `TestWebAdapterIsServingOnly` and the dependency rule for `internal/adapters/web`.
- **`internal/adapters/duckdb/dashboard_test.go`:** `TestDashboardHandleIsReadOnly`.
- **`cmd/jb/serve_test.go`:** the `--addr` and `--allow-remote` behaviour of the command.

Rules with no test, found by searching the tests of the web package, `cmd/jb` and `internal/archtest` for each name:

- **`Referrer-Policy: no-referrer`, `Cache-Control: no-store` and `Cross-Origin-Resource-Policy: same-origin`** are set in `New` and no test reads them.
- **The 20 second request budget** (`requestBudget`, `http.TimeoutHandler`) has no test.
- **The whole CSP string** is not compared. The test checks substrings.
- **No SQL route** is not asserted. The route list is the only evidence.
- **The store handle is closed** is checked on the run page only, not on every page.
- **Static JavaScript** is not scanned for `innerHTML`, `eval` or `document.write`.
- **Order of the method and Host checks** is not asserted.
- **The CSP in a real browser** is not tested.

## Reference implementations

**Shipped**

- Handler, CSP, headers, routes and limits: `internal/adapters/web/web.go`.
- Pages and view models: `internal/adapters/web/views.go` and the `*.templ` files, with generated `*_templ.go`.
- htmx configuration and link builders: `internal/adapters/web/ui.go`.
- Vendored libraries and project scripts: `internal/adapters/web/static/`.
- Provenance of the libraries: [docs/THIRD-PARTY.md](../THIRD-PARTY.md).
- Read-only store: `internal/adapters/duckdb/dashboard.go`.
- Command: `cmd/jb/serve.go`.
- Narrative description: [docs/ARCHITECTURE.md](../ARCHITECTURE.md), "The dashboard".

**Proposed**

None.

## Open questions

The maintainer decides each one.

- **Tests for the untested rules.** The Conformance section lists eight. Decide which are worth a test. The three headers and the whole-CSP comparison are cheap.
- **A scan of `static/*.js`.** Decide whether to extend the archtest rule, or add a test, to ban `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` and `eval` in `estate.js` and `sheet.js`.
- **Hash-based `script-src`.** Decide whether to adopt it, and if so whether `estate.js` and `sheet.js` would be generated with a hash at build time.
- **A doc disagreement.** docs/ARCHITECTURE.md says the scripts are "three vendored files and one of our own". The code and docs/THIRD-PARTY.md show two vendored files (`d3.min.js`, `htmx.min.js`) and two of this project (`estate.js`, `sheet.js`). The CSP and the page-script test agree with the second. Decide who corrects ARCHITECTURE.md. This RFC does not.
- **Local users.** Decide whether loopback with no authentication is enough on a shared machine, or whether a token option is wanted.
- **Request rate.** Decide whether the dashboard needs a limit on concurrent requests.
- **Spec index row.** docs/spec/README.md points the "Dashboard security model" row at ARCHITECTURE.md. Decide whether it should also point here.

## Changes

- 2026-11-06: back-filled from the shipped dashboard, its tests and CHANGELOG.md `[0.3.0]`. Status `implemented`.
