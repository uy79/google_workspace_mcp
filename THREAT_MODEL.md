# Google Workspace MCP — Pictorial Threat Model

This document converts the narrative threat model into diagrams so engineering and security reviews can quickly identify trust boundaries, attack surfaces, and mitigations.

## 1) System context diagram

```mermaid
flowchart LR
    subgraph ClientSide[Client / Caller Side]
      A1["MCP Client or AI Assistant (JSON-RPC or HTTP caller)"]
      A2["Attacker-controlled inputs: tool params, headers, callback params, document/email content"]
    end

    subgraph ServerHost[Google Workspace MCP Server Host]
      B1["FastMCP server (core/server.py, fastmcp_server.py)"]
      B2["Auth middleware and user binding (auth/auth_info_middleware.py, auth/service_decorator.py)"]
      B3["OAuth 2.1 session store (auth/oauth21_session_store.py)"]
      B4["Credential store (auth/credential_store.py)"]
      B5["Attachment storage (core/attachment_storage.py)"]
      B6["Path validation (core/utils.validate_file_path)"]
      B7["External URL fetch plus SSRF guards (gdrive/drive_tools.py)"]
      B8["Tool registry and scope enforcement (core/tool_registry.py, auth/permissions.py)"]
    end

    subgraph External[External Dependencies]
      C1["Google OAuth and Google APIs"]
      C2["External URLs from user-supplied fileUrl"]
      C3["Local filesystem for credentials, attachments, and uploads"]
      C4["Logs and observability"]
    end

    A1 -->|JSON-RPC or HTTP| B1
    A2 -->|Untrusted input reaches| B1
    B1 --> B2
    B2 --> B3
    B2 --> B4
    B1 --> B8
    B1 --> B5
    B1 --> B6
    B1 --> B7

    B2 <--> |OAuth tokens and userinfo| C1
    B8 <--> |Scoped API operations| C1
    B4 <--> C3
    B5 <--> C3
    B6 <--> C3
    B7 -->|Guarded HTTP fetch| C2
    B1 --> C4
```

## 2) Trust boundaries (DFD-style)

```mermaid
flowchart TB
    U["Untrusted or semi-trusted inputs: client params, headers, callback query, URL content"]
    T1{{"Boundary 1: MCP client to server"}}
    S["Workspace MCP server process"]

    T2{{"Boundary 2: Server to Google APIs"}}
    G["Google OAuth and Google Workspace APIs"]

    T3{{"Boundary 3: Server to local filesystem"}}
    F["Credential files, attachments, uploads"]

    T4{{"Boundary 4: Server to external URLs"}}
    X["Internet hosts and file URLs"]

    O["Operator-controlled config: env vars, tool tiers, storage backend settings"]

    U --> T1 --> S
    S --> T2 --> G
    S --> T3 --> F
    S --> T4 --> X
    O --> S
```

## 3) High-risk attack paths and defenses

```mermaid
flowchart TD
    A["Attacker goal: access or abuse protected data or actions"] --> B1["Cross-user data access"]
    A --> B2["Token theft or credential compromise"]
    A --> B3["SSRF to internal metadata or services"]
    A --> B4["Local file exfiltration"]
    A --> B5["Unsafe high-impact tool execution"]
    A --> B6["Attachment leakage"]

    B1 --> M1["Supply forged user_google_email"]
    M1 --> D1["Mitigation: OAuth 2.1 session binding and email override in service_decorator"]

    B2 --> M2["Read plaintext credential files or sensitive logs"]
    M2 --> D2["Mitigation: host hardening, secret hygiene, optional encrypted OAuth 2.1 storage"]

    B3 --> M3["Use fileUrl targeting metadata IPs or RFC1918 ranges"]
    M3 --> D3["Mitigation: DNS resolve checks, global IP validation, redirect validation, IP pinning"]

    B4 --> M4["Provide path outside allowlist or in secret directories"]
    M4 --> D4["Mitigation: validate_file_path allowlist plus secret path blocklist"]

    B5 --> M5["Exploit missing scope metadata or read-only bypass"]
    M5 --> D5["Mitigation: required scope decorators and tool registry permission filtering"]

    B6 --> M6["Obtain unauthenticated attachment URL"]
    M6 --> D6["Mitigation: high-entropy IDs and short TTL; residual risk remains in hosted mode"]
```

## 4) STRIDE-style control map

```mermaid
flowchart LR
    S["Spoofing: forged identity or email"] --> C1["Controls: session-bound credentials and verified token or userinfo checks"]
    T["Tampering: state, callback, or session misuse"] --> C2["Controls: single-use OAuth state and validated callback flow"]
    R["Repudiation: action ambiguity"] --> C3["Controls: operational logging with sensitive data handling"]
    I["Information disclosure: tokens, files, attachments"] --> C4["Controls: path restrictions, attachment TTL, secure storage posture"]
    D["Denial of service: large fetches or API abuse"] --> C5["Controls: URL fetch size limits and operational rate limiting"]
    E["Elevation of privilege: weak scope controls"] --> C6["Controls: scope-based tool filtering and tiered permissions"]
```

## 5) Criticality heatmap

```mermaid
flowchart TB
    subgraph Critical[Critical]
      C1[Cross-user auth/session bypass]
      C2[OAuth state validation bypass]
      C3[SSRF bypass to metadata services]
      C4[File path traversal outside allowlist]
    end

    subgraph High[High]
      H1[Credential theft after host compromise]
      H2[Read-only or write-scope bypass]
      H3[Attachment URL leakage before TTL]
    end

    subgraph Medium[Medium]
      M1[Prompt-injection-driven same-user actions]
      M2[API or resource exhaustion denial of service]
    end

    classDef critical fill:#ffdddd,stroke:#cc0000,stroke-width:2px;
    classDef high fill:#ffe8cc,stroke:#d97706,stroke-width:2px;
    classDef medium fill:#fff8cc,stroke:#a16207,stroke-width:2px;

    class C1,C2,C3,C4 critical;
    class H1,H2,H3 high;
    class M1,M2 medium;
```

## 6) Security review checklist tied to the model

- **Auth/session isolation**: verify no code path accepts caller-provided identity in OAuth 2.1 mode.
- **Scope gating**: ensure every new tool has explicit required scopes and is picked up by permission filters.
- **Filesystem boundary**: validate all local file operations pass `validate_file_path` allowlist logic.
- **External fetch safety**: preserve SSRF controls (DNS and IP checks, redirect checks, pinned destination).
- **Attachment confidentiality**: evaluate whether unauthenticated attachment routes need signed or authenticated access in hosted environments.
- **Operational controls**: enforce least-privilege scopes, rate limiting, secure logging, and secrets-at-rest hardening.
