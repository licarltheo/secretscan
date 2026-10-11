# secretscan

Fast git-secrets scanner in Go. Tuned for patterns that show up in real
C2 builds and live infra — the same signatures a defender would look
for in a stolen repository.

## What it detects

- **AWS** — access keys (AKIA, ASIA), secret keys, STS sessions
- **GitHub** — PATs (ghp_, github_pat_)
- **GitLab** — PATs (glpat-)
- **Slack** — bot, user, app, refresh tokens (xoxb-, xoxp-, xoxa-)
- **OpenAI** / **Anthropic** / **DeepSeek** — API keys
- **JWT** — any bearer token
- **Private keys** — RSA, EC, OpenSSH
- **.env files** — password=, secret=, api_key= patterns
- **Heroku** — API keys
- **npm** — auth tokens
- **Stripe** — sk_, pk_, rk_ live/test keys

## Build

```bash
go build -o secretscan .
```

## Usage

```bash
# text output, exit code 2 if findings
./secretscan -root .

# JSON for CI
./secretscan -root . -format json > findings.json

# scan a single repo
./secretscan -root ~/work/carl
```

## Exit codes

- 0 — clean
- 2 — findings present (CI-friendly)
- 1 — walk error

## Why this exists

The same regex signatures that detect leaked credentials on a public
repo also detect them in a stolen source tree. A C2 builder scanning
its own build output before exfil can prevent burning a real key.
A defender scanning a captured implant can extract the operator's
infrastructure keys.

## License

MIT
