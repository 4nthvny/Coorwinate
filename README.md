# Coordinate-Win

A Windows/WinRM port of [cpp-cyber's `coordinate`](https://github.com/cpp-cyber/blue/tree/main/Linux/coordinate).
Mass-deploys PowerShell scripts to a range of Windows hosts over WinRM for
CCDC-style blue-team work — think "a smaller, blunter Ansible you can carry as
a single binary."

Where the Linux original drives an interactive SSH shell and guesses when a
script finished by watching for marker strings, WinRM gives us a real command
model: each script runs as one remote command with its own **stdout, stderr,
and exit code**. That removes all the sleep/marker/`su`/`sudo` machinery.

## Build

```sh
go build -o coordinate .

# Cross-compile a static binary to drop on a Linux/Kali jump box or a Windows box:
GOOS=windows GOARCH=amd64 go build -o coordinate.exe .
GOOS=linux   GOARCH=amd64 go build -o coordinate .
```

## Usage

```sh
coordinate [flags] script1.ps1 [script2.ps1 ...]
```

Local admin across a /24, prompting for the password:

```sh
./coordinate -t 10.0.0.0/24 -u Administrator scripts/harden.ps1
```

Multiple creds, HTTPS (5986), several scripts, saving output:

```sh
./coordinate -t 10.0.0.5-10.0.0.40 -s -u Administrator,svc_admin -p 'P@ss1,P@ss2' \
  -o output scripts/harden.ps1 scripts/disable_smb1.ps1
```

Domain account (NTLM):

```sh
./coordinate -t 10.0.0.0/24 -u 'CORP\Administrator' -p 'P@ssw0rd' scripts/harden.ps1
```

### Flags

| Flag | Meaning |
|------|---------|
| `-t, --targets` | IPs: single, `A-B` range, or CIDR, comma-separated |
| `-u, --usernames` | Comma-separated usernames; `DOMAIN\user` or `user@domain` for AD |
| `-p, --passwords` | Comma-separated passwords (prompted if omitted) |
| `-P, --port` | WinRM port (default 5985, or 5986 with `-s`) |
| `-s, --https` | Use HTTPS |
| `-k, --insecure` | Skip TLS verification (default on; competition certs are self-signed) |
| `-b, --basic` | HTTP Basic instead of NTLM (needs `AllowUnencrypted` or HTTPS) |
| `-l, --limit` | Concurrent scripts per host (default 3) |
| `-T, --timeout` | Per-script timeout in seconds (default 60) |
| `-c, --callbacks` | IPs substituted into `#CALLBACK_IP` in scripts |
| `-E, --env` | PowerShell statements run before each script (`;`-separated) |
| `-o, --outdir` | Directory for per-host output files |
| `-C, --create-config` | Build `config.json` from `user,password` output lines |
| `-U, --use-config` | Use per-host creds from `config.json` |
| `-q`/`-d`/`-e`/`-y` | quiet / debug / errors-only / skip confirmation |

## How it works

1. One goroutine per target IP. A fast TCP check on the WinRM port skips dead hosts.
2. Credential spray: each `username × password` is tried with a `whoami` probe
   until one authenticates.
3. The host's scripts are fanned out across a worker pool bounded by `-l`.
4. Each script file is read locally, `#CALLBACK_IP` and `-E` env lines are
   applied, then the contents are piped over **stdin** to a tiny PowerShell
   bootstrap (`$code=[Console]::In.ReadToEnd();Invoke-Expression $code`). Sending
   the body over stdin sidesteps the ~8191-char command-line limit.
5. stdout/stderr/exit code are reported per host and optionally saved to
   `<outdir>/<hostname>.<script>.txt`.

### Authentication / encryption

By default Coordinate-Win uses **NTLM with message encryption**, so the payload
is protected even over plain HTTP — Windows refuses unencrypted WinRM unless
`AllowUnencrypted=true`. Use `-s` for HTTPS, or `-b` for Basic auth (which then
requires `AllowUnencrypted` or HTTPS).

### `config.json` flow

`scripts/password.ps1` rotates the current account's password and prints
`user,newpassword`. Run once with `-C` to capture those into `config.json`,
then use `-U` on later runs so each host is reached with its own new credential:

```sh
./coordinate -t 10.0.0.0/24 -u Administrator -p 'oldpass' -C scripts/password.ps1
./coordinate -U scripts/harden.ps1
```

## Preparing a target for WinRM

On each Windows host, as Administrator:

```powershell
Enable-PSRemoting -Force
# For non-domain / workgroup hosts, trust the subnet you manage from:
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '10.0.0.*' -Force
```

> Note: local admin accounts *other than* the built-in Administrator get a
> filtered (non-elevated) token over the network unless
> `LocalAccountTokenFilterPolicy=1` is set under
> `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.

## Notes vs. the Linux original

Several data races in the original are fixed here: console output is serialized,
and `brokenHosts` / `configEntries` are mutex-guarded. Output is appended
per-script rather than truncating the file on every script.

Use only on systems you are authorized to administer (e.g. your own CCDC team's
assigned hosts).
