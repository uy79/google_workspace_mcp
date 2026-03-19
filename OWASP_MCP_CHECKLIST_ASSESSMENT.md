# OWASP Practical Guide Assessment - Google Workspace MCP (Local Mode Only)

Date: 2026-03-19

## Scope

This assessment is **strictly for local mode usage** (local machine, user-run, non-proxy, non-multi-tenant).
Remote hosting/proxy controls are intentionally excluded in this version.

## Minimum baseline checklist (local mode)

| OWASP minimum baseline requirement | Status (Local Mode) | Detailed evidence (how met / why not met) | Gap and local recommendation |
|---|---|---|---|
| **1.1 All remote MCP servers use OAuth 2.1/OIDC** | **Not Applicable (local-only scope)** | For local stdio/CLI paths, OAuth 2.1 is not the primary control boundary. Code explicitly disables OAuth 2.1 in CLI mode by setting `MCP_ENABLE_OAUTH21=false` and `WORKSPACE_MCP_STATELESS_MODE=false`. | Keep local usage on stdio/single-user. If you ever expose HTTP remotely, reassess and enforce OAuth 2.1. |
| **1.2 Tokens are short-lived, scoped, validated on every call** | **Partially Met** | Scope checks are enforced before service execution (`has_required_scopes` checks and denial on missing scopes). External token session-time clamping exists, but local mode does not enforce one universal token-TTL policy for all credential paths. | Keep using least-privilege scopes (`--read-only` / `--permissions`) and document a local token rotation policy. |
| **1.3 No token passthrough; policy enforcement is centralized** | **Partially Met** | Auth context is centralized through middleware/context and service decorators, but local code paths still rely on credential/token material loaded from local stores and provider state (pragmatic for local usage). | Acceptable in local single-user mode; reduce risk by minimizing scopes and restricting who can access the workstation/profile. |
| **2.1 Users, sessions, execution contexts fully isolated** | **Mostly Met (for single-user local)** | Request/session context is separated via contextvars + session middleware and session binding logic is present. In local single-user mode, tenant-isolation complexity is low by design. | Keep single-user execution model; do not share the same local runtime across multiple OS users. |
| **2.2 No shared state for user data** | **Partially Met** | There is process-global in-memory state for sessions/metadata (e.g., global stores), which is acceptable-ish for single-user local mode but not strict isolation in principle. | Treat this as acceptable local tradeoff; avoid running mixed identities in one process. |
| **2.3 Deterministic cleanup and enforced resource quotas** | **Partially Met** | Deterministic cleanup exists for OAuth states and expiring attachments. Explicit hard resource quotas (per-user RAM/CPU/request budgets) are not evident for local mode. | Add optional local limits (max attachment size, max files, request throttling) if you want stricter baseline. |
| **3.1 Tools cryptographically signed, version-pinned, formally approved** | **Not Met** | No repo-native mechanism for cryptographic signing/formal approval workflow of tools was found. | Pin package versions in your local launcher/venv and maintain a local allowlist of approved versions. |
| **3.2 Tool descriptions validated against runtime behavior** | **Not Met** | No conformance harness was found that proves every tool description matches runtime behavior. | Add local smoke/conformance checks for critical tools you rely on. |
| **3.3 Only minimal necessary tool fields exposed to model** | **Partially Met** | Some minimization exists (e.g., auth/email handling abstraction), but overall tool surface remains broad due to product scope. | Run with restricted tool tiers/selected tools only. |
| **4.1 All MCP messages/tool inputs/outputs schema-validated** | **Partially Met** | FastMCP/typed tool patterns provide structure, but not every app-specific output appears to have explicit, uniform schema contracts in this repo. | Add explicit response models for high-risk tools if stricter guarantees are needed locally. |
| **4.2 Inputs/outputs sanitized, size-limited, untrusted** | **Partially Met** | Strong file-path sanitization and secret-path blocking are present. Cleanup/expiration exists for attachments, but universal hard size limits are not clearly enforced globally. | Add local maximum payload/attachment sizes and reject oversized requests early. |
| **4.3 Structured (JSON) tool invocation required** | **Partially Met** | Structured invocation exists, but local CLI pathways are flexible and not JSON-only everywhere. | Prefer JSON invocation patterns in local automation scripts. |
| **5.1 Server runs containerized, non-root, network-restricted** | **Partially Met (environment-dependent in local mode)** | Container metadata/config exists, but non-root/network restriction are deployment-environment choices, not strictly enforced by this repo alone. | If desired locally: run rootless container, loopback-only bind, and host firewall egress restrictions. |
| **5.2 Secrets in vaults and never exposed to LLM** | **Partially Met (local practice-dependent)** | Project uses env/credential storage patterns; local secret hygiene is operator-dependent. No built-in mandatory vault integration in this repo. | Store secrets in OS keychain/secure secret manager; avoid plaintext credentials where possible. |
| **5.3 CI/CD security gates, audit logs, continuous monitoring mandatory** | **Not Met (for strict OWASP baseline)** | Mandatory security-gate/monitoring enforcement is not evidenced as a hard requirement from this local repo snapshot. | For local-only use this may be optional; if needed, add pre-commit SAST/secrets/dependency scans. |

## Local-only conclusion

For your intended local usage, the practical baseline is:

1. Run single-user local mode.
2. Use least-privilege scopes/tool selection.
3. Keep secrets in secure local stores.
4. Restrict local file access directories.
5. Pin versions of dependencies/tooling.

Under that local threat model, the current server is usable with sensible safeguards, but it does **not** fully satisfy every strict OWASP enterprise baseline item out-of-the-box.

## Evidence references (files reviewed)

- `main.py`
- `core/server.py`
- `auth/service_decorator.py`
- `auth/oauth21_session_store.py`
- `auth/auth_info_middleware.py`
- `auth/external_oauth_provider.py`
- `core/utils.py`
- `core/attachment_storage.py`
- `auth/oauth_config.py`
- `auth/credential_store.py`
- `smithery.yaml`
