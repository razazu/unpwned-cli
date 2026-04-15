<p align="center">
  <h1 align="center">UNPWNED CLI</h1>
  <p align="center">Website security scanner in your terminal. Zero config. One command.</p>
  <p align="center">
    <a href="https://www.npmjs.com/package/unpwned"><img src="https://img.shields.io/npm/v/unpwned" alt="npm version"></a>
    <a href="https://www.npmjs.com/package/unpwned"><img src="https://img.shields.io/npm/dm/unpwned" alt="downloads"></a>
    <a href="https://github.com/razazu/unpwned-cli/stargazers"><img src="https://img.shields.io/github/stars/razazu/unpwned-cli" alt="stars"></a>
    <a href="https://github.com/razazu/unpwned-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/razazu/unpwned-cli" alt="license"></a>
  </p>
</p>

<p align="center">
  <img src="assets/demo.png" alt="UNPWNED CLI scanning a website" width="600">
</p>

## Quick Start

```bash
npx unpwned scan yoursite.com
```

That's it. No signup, no API keys, no configuration.

## What It Checks

| Check | What It Looks For |
|-------|-------------------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **SSL/TLS** | Certificate validity, expiration, protocol version (TLS 1.2+), self-signed detection |
| **DNS Security** | SPF, DMARC, DKIM, DNSSEC |
| **Cookie Security** | Secure, HttpOnly, SameSite flags |
| **CORS Policy** | Wildcard origins, credential leaks, origin reflection |
| **Sensitive Files** | Exposed .env, .git/config, package.json, wp-config.php, and more |
| **Tech Stack** | Framework and hosting detection (Next.js, React, WordPress, Vercel, etc.) |

## Output Formats

### Terminal (default)

Beautiful colored output with progress bars, scores, and severity-sorted findings.

### JSON (for CI/CD)

```bash
npx unpwned scan yoursite.com --json
```

Returns structured JSON for piping into other tools or CI/CD pipelines.

**Exit codes:** `0` if score >= 50, `1` if score < 50 (use in CI to fail builds).

## CI/CD Example

```yaml
# .github/workflows/security.yml
name: Security Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Security scan
        run: npx unpwned scan ${{ vars.SITE_URL }}
```

## Scoring

Each check is weighted and produces a score from 0-100:

| Check | Weight |
|-------|--------|
| Security Headers | 25% |
| SSL/TLS | 20% |
| DNS Security | 20% |
| Cookie Security | 10% |
| CORS Policy | 10% |
| Sensitive Files | 10% |
| Tech Stack | 5% (informational) |

**Grades:** A+ (95-100), A (85-94), B (70-84), C (50-69), D (30-49), F (0-29)

## Want the Full Picture?

UNPWNED CLI checks 7 categories. [UNPWNED](https://unpwned.io?ref=cli) runs **36 security scanners** with AI-powered analysis, fix instructions, PDF reports, and continuous monitoring.

[Get your full security report](https://unpwned.io?ref=cli)

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - see [LICENSE](LICENSE) for details.

Built by [Raz Azulay](https://github.com/razazu) at [UNPWNED](https://unpwned.io).
