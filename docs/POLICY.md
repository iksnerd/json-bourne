# Policy: passive only

[Back to the README](../README.md)

`jb` is a passive tool, and it is inward-facing: it analyses your own logs and your own infrastructure. Outward reconnaissance (subdomain enumeration, search-engine discovery, URL gathering) and every active scan (port, HTTP, TLS, template scanning) are done by another runner outside `jb`. Their output can enter an estate file only through `jb estate facts import`, which reads a file or standard input and contacts nothing. `jb` runs none of those tools and wraps no external binary.

**It has no action role.** A plugin can only turn a log document into an event. Nothing in `jb` lets a plugin, a detector or an operator command change another system: there is no "block this address", no "rotate this key", no remediation step. So `jb` has no approval step, no record of who approved what, and no scheme for handing a plugin a credential for one action. The credentials `jb` reads are the ones in your config, named by environment variable, used by the sources and feeds you enabled. If a feature that acts is ever proposed, it needs a design of its own for approval and credentials first; it does not arrive as a flag on an existing command. See [adr/0001-relationship-to-other-plugin-specifications.md](adr/0001-relationship-to-other-plugin-specifications.md).

- It never sends a packet to a host you do not operate.
- It has no scanner, no probe, no fuzzer and no exploit code. The `newkey` history probe (RFC 0014) is not one: it counts events in the operator's own index, through the source already configured, by sending the candidate keys in a request body to that index and to no other host.
- Its sources read only your own logs and telemetry, through credentials you supply, over transports you configured.
  - The one source today, `kibana`, sends requests to the Kibana URL in your config and nowhere else.
  - The reputation feeds (`jb intel`) are `greynoise` and `sans-isc`, which send requests to the feed API in your config and nowhere else, and `dnsbl`, which asks a DNS resolver a question under a blocklist zone. Each asks about an address and none contacts the address.
  - `jb estate IP` asks a DNS resolver for an address's PTR record and an RDAP service for its registration, and never contacts the address either: the RDAP adapter's dialer refuses a connection to it. `jb estate asn|dns|ct` add three more passive collectors with the same rule (see "Estate sources" below).
  - The alert webhook (`jb watch`, `alerts:`) is outbound notification, not collection. It POSTs a short finding summary to the URL you configured and to no other host, and reads nothing from the target network.
  - `net/http` as a client is confined to these seven adapters by `internal/archtest`: `kibana`, `greynoise`, `sansisc`, `rdap`, `bgp`, `crtsh`, `webhook`. The DNS adapters (`dnsbl`, `dnsptr`, `dnsfwd`) have no HTTP at all.
  - `jb serve` (`internal/adapters/web`) is the one other importer. It answers requests from a browser on this machine and makes none. archtest allows it only an allowlist of serving identifiers, so `http.Get`, `http.Client`, `http.NewRequest`, `http.Transport` or `net.Dial` in that package fails the build. It binds loopback unless `--allow-remote` is passed, has no authentication, and shows evidence that is already on disk. It adds no collection.
- Analysis runs on evidence already in the local database. Detectors read through `core.EventReader` and nothing else; archtest forbids importing `net/http` or `os/exec` in the detector package, and `net/http` in the storage package.
- A process is started only for two reasons: `git`, to check that the evidence directory is ignored (`internal/casefile`), and a mapper plugin the operator allowlisted (`internal/adapters/plugin`). `os/exec` is confined to those two packages by `internal/archtest`. See "Mapper plugins: what runs on the machine" below.

## Why

**Evidence chain.** Logs you already hold are evidence whose provenance you can state. Traffic you generate against someone else's system is new data of uncertain standing, mixed into a case whose value depends on being able to say exactly where each fact came from.

**Tipping off.** Probing the infrastructure behind an attack announces that you are looking. The operator can rotate, wipe or move, and you lose the observation window that passive collection keeps open.

**A victim host is someone else's intrusion.** Attack traffic often comes from machines that were themselves compromised. Touching one can disturb their evidence, break their service or cross a legal line, against a party who is also a victim.

**The provider route is stronger.** An abuse report or preservation request to the network or hosting provider, backed by your own logs, can lead to action that nothing you do from outside can match, and it does so through a channel that has standing.

## Estate sources

An estate file (`jb.estate/v2`, `docs/CASE-SPEC.md` section 4.5) records infrastructure relationships. It may cite only passive sources: public registries, resolvers and logs that answer about an address or name without `jb` contacting the infrastructure. The loader rejects any other `source`, and a test keeps this list equal to the code.

<!-- estate-sources:begin -->
- `rdap`: RIR and registry RDAP answers about an address, AS or domain.
- `rdns`: the PTR record for an address, asked of a DNS resolver.
- `dns`: forward records for a name, asked of a DNS resolver.
- `whois`: a registry's WHOIS answer, fetched from the registry.
- `crt.sh`: certificate transparency search results, from a public search service.
- `ct-log`: entries read from a certificate transparency log.
- `bgp`: routing and origin-AS data, from a public BGP data service (RIPEstat-style API) fed by route collectors.
- `passive-dns`: a passive DNS database's record of past resolutions.
- `scan-cache`: a store of past observations that someone else collected earlier (open ports, exposed services, known vulnerabilities), read from an export file the operator already holds. `jb` has no network code for it; `jb estate facts import FILE` reads the file from disk and nothing leaves the machine.
<!-- estate-sources:end -->

No scanner, port probe, banner grab, TLS handshake or HTTP request to the target is a source, whatever it is called. An address is looked up in a registry or resolver; the address itself is never contacted. Adding a source is a change to this list and to `casefile.EstateSources` in the same commit.

### The test for a source

A source is passive when the target observes nothing from `jb`. The test is what the target sees, not what the source is called. A store of past observations that a third party collected earlier (for open ports, exposed services or known vulnerabilities) passes: `jb` asks the store, and the address is never contacted. A service that scans on demand when asked does not pass, because the request makes it touch the target.

A source that passes the test joins the list above under its own name. If `jb` itself asks the source over the network, it sends the address to a third party, is off by default and needs the `estate.external` switch like the other external services. A source `jb` only reads from a local file the operator obtained (`scan-cache`) sends nothing and needs no switch. Each new source is judged by this test and recorded as a change to this file.

Decided 2026-11-06 by the maintainer: a cached third-party store passes the test. The first one is the role `scan-cache`. It names a role and not a vendor, so any export the operator converts to the neutral import shape (`docs/CASE-SPEC.md` section 4.5.2) counts. A collector that queries a named service would be a separate source name, behind `estate.external`, and a separate change to this file.

### What leaves the machine

Passive towards the target is not the same as nothing sent. `jb estate asn` (source `bgp`) and `jb estate ct` (source `crt.sh`) ask a third-party service, so the AS numbers, addresses and domain names you ask about leave the machine to that service and are visible to its operator. `jb estate dns` (source `dns`) sends the names to a resolver, which asks the domain's own name servers on your behalf; `jb` itself never connects to the domain or to anything it resolves to. Each of the three is **off by default** and is switched on one by one in the case config (`estate.external`, `docs/config/estate.md`); until it is, the command refuses and sends nothing. Use `dns` only for a domain you own or are authorised to profile. The older `jb estate IP` lookups (reverse DNS, RDAP) are not behind the switch: they send only the address, to a resolver and a registry.

Every collector is bounded: a timeout per request, a response size cap, a cap on targets per run (a longer list is refused, not truncated), a minimum interval between requests, and a cap on results. A result cut at a cap, a timeout, a 429 or any non-2xx answer ends the run INCOMPLETE with exit status 1; a failed lookup stores nothing.

Reading rules: a certificate transparency name is a candidate, not a confirmed host, and a wildcard certificate names none. A CDN, proxy or shared-hosting address, prefix or origin AS identifies the provider, not who runs the site.

An estate map shows who owns and runs infrastructure. It does not show who typed the commands, and a CDN or proxy edge address says nothing about the visitor behind it.

### Estate drift: passive only, and what is not ported

`jb estate refresh` and `jb estate diff` watch the operator's own estate for change over time, and stay inside the list above: DNS, RDAP, certificate transparency and BGP data, through the same adapters, the same per-service switches (`estate.external`), the same caps and spacing, and the same rule that a failed or cut lookup makes the run INCOMPLETE. `diff` reads two local files and sends nothing. `refresh` asks again only what the estate file records having asked; it never widens the target set, and `--max-targets` refuses a longer list rather than truncating it. What leaves the machine is exactly what the original `jb estate` commands send (the domains, addresses and AS numbers already in the file, to a resolver, a registry, crt.sh and a BGP service).

Deliberately not ported from `wha watch`: port scans of the estate's hosts, HTTP or TLS probes of them (status, certificate or header checks), and GitHub lookups for the organisation. Each of those sends traffic to a host or service that is the subject of the check. `jb` is passive only; an active check, even against assets the operator owns, needs an authorisation model (a declared scope the targets are checked against, an explicit per-run authorisation, and a record of who authorised what) that `jb` does not have, and the section "Changing the policy" below is the route for adding one. Until then the estate drift check answers what public registries, resolvers, logs and route collectors say changed, not what a probe would find. A reader should not infer that a host is unchanged from the absence of drift: the check cannot see an open port or a changed certificate on a live host.

Reading rules for drift: an address, prefix or origin AS that belongs to a CDN, proxy or shared-hosting provider changes for reasons that say nothing about ownership, and the output says so; a certificate-transparency name is a candidate, not a live host; a change of resolver or service is a change of method and is listed as not comparable, never as drift.

## Reputation feeds: what leaves the machine

A reputation lookup sends the address you ask about to a third party, so it is not nothing. `jb doctor` lists each service with its state and this sentence.

- `greynoise`: the address, in the request path, to the GreyNoise API host in your config, with your API key in a header when you named one.
- `sans-isc`: the address, in the request path, to the SANS Internet Storm Center, with no credential.
- `dnsbl`: the address, written as a DNS name under the blocklist zone, to the DNS resolver (yours, or the system's) and, through it, to the operator of the zone, who can log it. Because a recursive resolver also passes the name to authoritative servers, treat it as visible to all of them. It is **off unless `enabled: true`** in the feed's config; a listed but disabled feed sends nothing.

A reputation answer is context, not attribution: it describes an address as a third-party sensor or list saw it, a CDN or proxy edge address says nothing about the visitor, and it never reaches a detector or changes a finding's severity (`internal/archtest` fails the build if a detector, the hunt or the watch imports or mentions a feed). A feed that failed, timed out, was rate limited, or (for a DNSBL) refused the resolver is a failed lookup that ends the run `INCOMPLETE`; it is never read as "not listed".

`jb doctor --online` makes one TCP connect per service host and sends no bytes. It is the only reachability check, and it sends no credential and no webhook URL.

## Mapper plugins: what runs on the machine

A source with `mapper: plugin:<name>` starts the executable you allowlisted for that name, as your user, once per run, and writes every fetched document to it. This is not collection and sends nothing to a remote host by itself. It is code running on your machine with your privileges and your files, handed your evidence.

- **Only you allow a plugin.** The allowlist is `$JB_PLUGINS_FILE` or `~/.jb/plugins.yaml`, jb's own file. A case names a plugin by name and can never add a path, a command or an entry. An optional sha256 pin is checked before every launch, and a file or directory writable by group or others, or a symlink out of the plugin directory, is refused.
- **The child gets almost nothing.** Its environment is empty but `PATH`, `HOME`, `LANG` and `TMPDIR`; no API key of jb's reaches it. Its working directory is its own.
- **jb does not sandbox it and does not stop it using the network.** The OS is not asked to enforce anything. If the plugin must not call out, enforce that outside jb. The examples in `examples/plugins/` import no network code, and archtest fails the build if they do.
- **A plugin cannot make a result look clean.** A timeout, a crash, bad output, a wrong result count or a refused launch fails the source, so the run is INCOMPLETE (exit 1).

Details and the list of what is not enforced: [PLUGINS.md](PLUGINS.md).

## Changing the policy

An active capability (anything that sends traffic to a host outside your control) is not accepted as a routine contribution. It would need, at minimum:

1. A documented decision, as a change to this file, that states the scenario, what it will touch, and why passive collection is not enough.
2. An explicit authorisation flag that the operator must pass on each invocation, refused by default, so the capability cannot run by accident or from a config file alone.
3. A scope check that names the targets the operator asserts they are authorised to test.
4. Tests showing that without the flag the code path refuses to send anything.

Proposals that do not meet all four will be closed.
