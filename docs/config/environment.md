# Environment and credentials

This page covers `jb doctor` and how credentials reach `jb`.

## Checking the environment

`jb doctor [--case DIR | --config FILE] [--online] [--output table|json]` answers "will the next run work, and what would it send?" without running one. It is read-only, makes no network connection unless `--online` is given, and exits 0 only if no check failed.

| Group | What is checked | Result |
|---|---|---|
| `build` | jb version and commit, the Go version, the DuckDB driver module version and the engine version (read from a private in-memory database, so it also proves the cgo library loads) | ok, or fail if the engine does not start |
| `case` (with `--case`) | the same checks as `jb case check`: `case.yaml`, the evidence directory is ignored by git (the existing guard), actors, estate, each listed config and the case files its detectors name | fail on any problem; "not a git work tree" is a warning, not a pass |
| `config` | the config loads strictly (unknown keys and types are errors). Each source or detector with `enabled: false` gets a `skipped` line `DISABLED: ...`. With `--case`, every config the case lists, or the one `--config` chooses. A `mapper: plugin:<name>` that is not in the operator's allowlist fails here | ok or fail |
| `plugins` | the operator's allowlist (`$JB_PLUGINS_FILE` or `~/.jb/plugins.yaml`): each plugin's path, pin state (`none`, `ok`, `MISMATCH`) and the file, directory and symlink checks, without launching any. No environment value is shown | ok, fail for a plugin that would be refused, skipped when nothing is allowlisted |
| `env` | each environment variable a source, feed or alert names (`api_key_env`, `url_env`) is set and non-empty. Reported as `set` or `unset`, **never the value and never its length**; the check cannot see either, because the port that answers it returns a boolean. A variable named by a disabled service, or by a source or detector with `enabled: false`, is skipped | fail when an enabled service's variable is unset: the command that uses it would refuse to run |
| `store` | the store path (in a case, `<case>/evidence/jb.duckdb` unless the config sets one) is writable by this user, an existing file is owned by this user, is not group- or world-writable (warning), and opens read-only with a schema this build understands (an older schema is a warning, a newer one a failure). A file that does not exist yet is `skipped`: the first run creates it, and doctor creates nothing | ok, warn, fail or skipped |
| `online` | only with `--online`, see below | |

After the checks, **services** lists every outbound service the config names (kibana sources, feeds, the webhook, and the three estate collectors), each `enabled` or `disabled`, with what would leave the machine if the command that uses it ran. A `dnsbl` feed says the address goes to a resolver and the zone's operator; the estate collectors are disabled until `estate.external` lists them.

`--online` makes one TCP connect, bounded to 4 seconds, to each distinct host of an enabled service, and then closes it. **No bytes are sent**: no HTTP request, no credential, no webhook URL. For a webhook the host and port are taken from the URL held in its environment variable, and the path, query and user info are never read into output. Services that are reached through a DNS resolver over UDP (`dnsbl`, `estate dns`) are listed and not probed, because a TCP connect would not test them. A TCP connect does not use `HTTP_PROXY`: on a network where outbound traffic must go through a proxy, an unreachable result may only mean "not directly".

The `store` group also does two things that need the engine. A store another process holds read-write is waited for 3 seconds (not `JB_DB_LOCK_WAIT`), then reported as a **fail** that names the holder's executable and PID when DuckDB gives one. And when the store opens, the last 24 hours are checked for one set of documents stored under two source labels, a **warn** (never a fail) that prints the `jb db rename-source` fix ([Source labels and double counting](store.md#source-labels-and-double-counting)).

`skipped` is not a pass. It means the thing is not configured or was not asked for (no `--case`, no store file yet, no `--online`). The result line says so, and a bare `jb doctor` with neither `--case` nor `--config` checks the environment only.

doctor does not inventory external binaries (the ProjectDiscovery tools or any other): jb wraps none, so there is nothing to find, version or wire.

## Credentials

The file never holds a credential. A source names an environment variable (`api_key_env`) and `jb` reads it when it builds the sources, in `hunt`. `db status` and `serve` load the file only to find the database path and read no credential.

- Set the variable in the environment that starts `jb`: see [Supplying credentials](#supplying-credentials). Do not export it in a file you commit.
- A missing or empty variable is an error that names the variable and never prints a value.
- A value pasted into `api_key_env` or `url_env` (lower case, `=`, `:`, `/` and so on) is refused at load without echoing it.
- The key is sent in an `Authorization: ApiKey` header only. It is not put in URLs, and the HTTP error text omits the response body.
- `.gitignore` excludes `.env`, `*.duckdb` and `/evidence/`. Keep real configs out of version control anyway: they name your hosts and indexes.

## Supplying credentials

`jb` reads a credential from its process environment and from nowhere else. It has no `--env-file` flag, does not read a `.env` file and does not take a value on the command line. The YAML holds only the variable name (`api_key_env: JB_KIBANA_API_KEY`). Whatever starts `jb` puts the value in the environment. This keeps file permissions, ownership and logging of the secret in the hands of the operator's own launcher.

When a variable is missing or empty, the error names it and says it is read from the process environment. Check the name against the config, then use one of these.

A shell, reading a file you own and keep outside the repository (mode 600):

```sh
set -a                      # export every variable the file sets
. "$HOME/.config/jb/secrets.env"
set +a
jb hunt --config jb.yaml
```

The file holds `JB_KIBANA_API_KEY=...` lines and nothing else. The variables reach `jb` and its children only.

One command, from a keychain or secret manager (the second line is an example for macOS):

```sh
JB_KIBANA_API_KEY="$(security find-generic-password -s jb-kibana -w)" jb hunt --config jb.yaml
```

A service manager. A systemd unit names the file in `EnvironmentFile=/etc/jb/secrets.env` (mode 600, owned by the service user), and `jb watch --case DIR` inherits it. Cron and containers have an equivalent: set the variable in the job's environment, not in the config.

The Go package takes the lookup as `Env` and does not touch the process environment when it is set:

```go
env := func(name string) (string, bool) {
	v, ok := secrets[name] // from your own store
	return v, ok && v != ""
}
res, err := jb.HuntCase(ctx, caseDir, jb.CaseHuntOptions{HuntOptions: jb.HuntOptions{Env: env}})
```

Rules that hold in every recipe: the YAML never holds the value, a value is never put on a command line (it shows in the process list), and `jb` never prints it.

[Back to the configuration index](../CONFIG.md)
