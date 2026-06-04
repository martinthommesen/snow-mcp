# Security Policy

## Supported Versions

This repository is pre-GA. Security fixes target `main` and the current release branch, if one
exists. Production deployments should pin a commit SHA and record it in `docs/PRODUCTION_READINESS.md`.

## Reporting A Vulnerability

Do not open a public issue for a vulnerability, suspected secret exposure, or live-instance
security incident. Contact the repository owner privately and include:

- affected commit SHA and deployment environment,
- exact endpoint/tool/ServiceNow path involved,
- reproduction steps that do not include real tokens, credentials, PII, or customer data,
- observed impact and whether exploitation was confirmed.

The owner should acknowledge within two business days, triage severity, and coordinate a fix,
workaround, or risk acceptance. If a secret may have been exposed, rotate it first, then analyze.

## Security Gates

Before a production release, run the local gates in `.github/workflows/ci.yml`, then run the
manual `live-subprod-gates` workflow against a non-PDI sub-production ServiceNow instance. Record
the resulting evidence in `docs/PRODUCTION_READINESS.md`.
