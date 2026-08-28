# easydmarc-mcp

MCP server for **EasyDMARC** — an email authentication / anti-phishing
platform. EasyDMARC monitors a domain's DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT
DNS setup and aggregates the DMARC reports mailbox providers send back, so
an MSP can see whether a client domain is protected against spoofing and
fix misconfigurations. This server exposes an MVP subset of EasyDMARC's
public partner/MSP-tenant REST API as MCP tools.

## Overview

- Stateless HTTP service. No credentials are ever persisted — each request
  supplies its own bearer token via a header, used only for the lifetime
  of that single request.
- Supports concurrent requests; per-request credential isolation is done
  via Python `contextvars`, not a global/shared client instance.
- Entry points: `POST /mcp` (MCP protocol) and `GET /health` (health check).
- Default port: `8080` (configurable via `MCP_HTTP_PORT`).

## Scope

**24 tools**, an MVP subset of EasyDMARC's ~95-endpoint public API (see
[API Reference](#api-reference)), scoped by explicit decision to the
email-authentication-specific surface an MSP agent actually needs:

| Category | Count | Covers |
|---|---|---|
| `organizations` | 2 | List/get client organizations (the partner-tenant scoping entry point) |
| `domains` | 7 | Onboard/list/get/update/delete a domain, get/verify its DMARC DNS setup |
| DNS lookup | 7 | Live DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT record checks |
| `rua` (aggregate reports) | 5 | Report history, auth pass-rates, volume, volume-over-time |
| `failure-reports` (RUF) | 3 | Forensic failure report list/detail/aggregates |

Cut entirely (see **Known Gaps**): generic DNS record types (A/AAAA/MX/NS/
PTR/TXT/CNAME — not EasyDMARC-specific), the newer DNS Intelligence batch
surface, Webhooks, Billing/Subscriptions/Invoices, Users, Audit Log,
Partner Profile, and the RUA `aggregations`/`properties` endpoints
(overlap with `auth-pass-rates`/`volume` for the same data, sliced
differently).

## Authentication

EasyDMARC's public API authenticates with a bearer **JWT access token**
(`Authorization: Bearer <token>`, obtained via EasyDMARC's own auth flow —
see API Reference). This server accepts an already-issued token per
request and forwards it exactly that way; it never performs its own
OAuth/token exchange.

### HEADER 授权参数说明

| Header | 类型 | 是否必填 | 默认值 | 枚举值 | 字段描述 | Example |
|---|---|---|---|---|---|---|
| `X-EasyDMARC-Token` | string | 是 | 无 | 无 | EasyDMARC bearer JWT access token，原样转发为上游 `Authorization: Bearer <token>` | `eyJhbGciOi...` |

Missing the header returns `401`:
```json
{
  "error": "Missing credentials",
  "message": "This server requires the X-EasyDMARC-Token header",
  "required_headers": ["X-EasyDMARC-Token"],
  "optional_headers": []
}
```

## Environment Variables

| Variable | 类型 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `MCP_TRANSPORT` | string | 否 | `stdio` | `http`（生产）或 `stdio`（本地开发） |
| `MCP_HTTP_PORT` | int | 否 | `8080` | HTTP 监听端口 |
| `MCP_HTTP_HOST` | string | 否 | `0.0.0.0` | HTTP 监听地址 |
| `AUTH_MODE` | string | 否 | `gateway` | `gateway`（生产，逐请求从 Header 取 token）或 `env`（仅本地开发，共享单一 token） |
| `EASYDMARC_API_TOKEN` | string | 仅 `env` 模式必填 | 无 | 共享 bearer token（仅本地开发） |
| `EASYDMARC_BASE_URL` | string | 否 | `https://api.easydmarc.com` | EasyDMARC API 基础 URL |
| `EASYDMARC_AUTH_HEADER` | string | 否 | `X-EasyDMARC-Token` | gateway 模式下承载 token 的 Header 名 |

## MCP Endpoint

- `POST /mcp` — MCP protocol (streamable HTTP transport)
- `GET /health` — health check, returns `{"status": "ok", "transport": "http", "auth_mode": "gateway"}` (pure local liveness probe, does not depend on the EasyDMARC API)

## Tool List

| Category | Tool | 功能 | 方法+路径 | 主要参数 |
|---|---|---|---|---|
| organizations | `easydmarc_list_organizations` | 列出该 partner 下的客户组织 | GET /v1/organizations | page, limit, order |
| organizations | `easydmarc_get_organization` | 按 ID 获取一个组织详情 | GET /v1/organizations/{id} | organization_id(必填) |
| domains | `easydmarc_list_domains` | 列出某组织下已接入的域名 | GET /v1/domains | organization_id(必填), page, page_size |
| domains | `easydmarc_get_domain` | 获取单个域名的接入详情 | GET /v1/domains/{domain} | organization_id(必填), domain(必填) |
| domains | `easydmarc_create_domain` | 接入新域名 | POST /v1/domains | organization_id(必填), domain(必填), type, group_id |
| domains | `easydmarc_update_domain` | 部分更新域名类型/分组 | PATCH /v1/domains/{domain} | domain(必填), domain_name, type, group_id |
| domains | `easydmarc_delete_domain` | 移除域名（破坏性，需 confirm=true） | DELETE /v1/domains/{domain} | organization_id(必填), domain(必填), confirm(必填) |
| domains | `easydmarc_get_domain_setup` | 获取应发布的 DMARC DNS 记录 | GET /v1/domains/{domain}/setup | organization_id(必填), domain(必填), record_type(必填, CNAME\|TXT) |
| domains | `easydmarc_verify_domain_setup` | 触发验证域名记录是否已生效（⚠️ 官方文档标注"Not available yet"） | POST /v1/domains/{domain}/setup | domain(必填), managed, tags |
| dns lookup | `easydmarc_lookup_dmarc` | 实时查询域名当前 DMARC 记录 | GET /v1/dns-lookup/dmarc | domain(必填), recommended_rua, skip_our_addresses |
| dns lookup | `easydmarc_lookup_spf` | 实时解析 SPF 记录完整 include 链 | POST /v1/dns-lookup/spf | domain(必填), max_age_ms |
| dns lookup | `easydmarc_lookup_spf_result` | 实时查询 SPF 校验结果摘要（含10次查找上限判定） | POST /v1/dns-lookup/spf/lookup-result | domain(必填), max_age_ms |
| dns lookup | `easydmarc_lookup_dkim` | 实时查询指定 selector 的 DKIM 记录 | GET /v1/dns-lookup/dkim | domain(必填), selectors(必填) |
| dns lookup | `easydmarc_lookup_bimi` | 实时查询 BIMI 记录 | GET /v1/dns-lookup/bimi | domain(必填), max_age_ms |
| dns lookup | `easydmarc_lookup_tls_rpt` | 实时查询 TLS-RPT 记录 | GET /v1/dns-lookup/tls-rpt | domain(必填), max_age_ms |
| dns lookup | `easydmarc_lookup_mta_sts` | 实时查询并校验 MTA-STS 记录+策略文件 | GET /v1/dns-lookup/mta-sts | domain(必填), max_age_ms |
| rua reports | `easydmarc_get_rua_reports` | 列出原始 RUA(聚合)报告记录 | POST /v1/dmarc/rua/reports | domain_names(必填), report_type(必填), date_from(必填), date_to(必填) |
| rua reports | `easydmarc_get_rua_report` | 按 UUID 获取单条 RUA 报告 | GET /v1/dmarc/rua/reports/{id} | report_id(必填) |
| rua reports | `easydmarc_get_rua_auth_pass_rates` | 获取 SPF/DKIM 认证通过率 | POST /v1/dmarc/rua/auth-pass-rates | domains_with_report_types(必填), date_from(必填), date_to(必填) |
| rua reports | `easydmarc_get_rua_volume` | 获取邮件总量（按字段分组） | POST /v1/dmarc/rua/volume | domains_with_report_types(必填), date_from(必填), date_to(必填) |
| rua reports | `easydmarc_get_rua_volume_history` | 获取按天/周/月分桶的邮件量趋势 | POST /v1/dmarc/rua/volume-history | domains_with_report_types(必填), date_from(必填), date_to(必填) |
| failure reports | `easydmarc_get_failure_reports` | 列出 RUF(取证)失败报告 | GET /v1/dmarc/failure-reports | organization_id(必填), domains(必填) |
| failure reports | `easydmarc_get_failure_report` | 按 ID 获取单条失败报告详情 | GET /v1/dmarc/failure-reports/{id} | organization_id(必填), report_id(必填) |
| failure reports | `easydmarc_get_failure_report_aggregates` | 按维度聚合失败报告统计（谁发的失败邮件最多） | GET /v1/dmarc/failure-reports/aggregates | organization_id(必填), domains(必填), dimensions(必填) |

`easydmarc_get_rua_*` 四个分析类工具的 `filters` 参数、`easydmarc_get_rua_volume*` 的 `group_by_fields` 等高级过滤/分组字段，本工具未做完整枚举校验，透传给 EasyDMARC API 自身校验——详见下方 Known Gaps。

## 测试示例

```bash
# Health check
curl -s http://localhost:8080/health

# Call a tool via the MCP protocol (streamable HTTP) — requires an
# initialize handshake first per the MCP spec; abbreviated example below
# shows the tool-call request body only:
curl -s -X POST http://localhost:8080/mcp \
  -H "X-EasyDMARC-Token: <your-easydmarc-bearer-token>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: <session-id-from-initialize>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "easydmarc_list_organizations",
      "arguments": {}
    }
  }'
```

## API Reference

- Support article: https://support.easydmarc.com/knowledge-base/easydmarc-public-apis
- Developer docs (Docusaurus site): https://developers.easydmarc.com/
- Official OpenAPI 3.0 spec (source of truth used for this build): https://github.com/easydmarc/public-api-docs/blob/master/specs/easydmarc-openapi.json

## Known Gaps

- **⚠️ UNVERIFIED against a live deployment.** This build was written
  entirely from EasyDMARC's own published OpenAPI spec
  (`easydmarc/public-api-docs`), following the "verify against the real
  spec, not impression" rule — but no call in this codebase has been
  exercised against a real, authenticated EasyDMARC account. Live probing
  during development found every documented path under
  `https://api.easydmarc.com` (including ones needing no auth) returns a
  plain Express `Cannot GET/POST <path>` 404 — while the bare `/v1` root
  does respond with an `EasyDMARC Public API v1` banner, confirming the
  host is real but suggesting these specific routes are not registered on
  it. This may mean the spec describes endpoints ahead of what's actually
  deployed (one endpoint's own description literally says "Not available
  yet" — see `easydmarc_verify_domain_setup`), or that a real API key/
  account is required to discover the correct base URL (EasyDMARC's own
  support article says the Public API documentation link only appears
  after clicking "Generate Key" inside the app). **Needs re-verification
  with a real EasyDMARC API token before being treated as functionally
  correct**, not just schema-correct.
- **MVP-scoped by explicit decision**, not a full port of the ~95-endpoint
  spec: cut generic DNS record types (A/AAAA/MX/NS/PTR/TXT/CNAME — any DNS
  tool can resolve these, not EasyDMARC-specific), the newer "DNS
  Intelligence" batch-check surface, Webhooks, Billing/Subscriptions/
  Payment/Invoices, Users, Audit Log, Partner Profile, domain batch-create,
  and the RUA `aggregations`/`properties` endpoints (overlap with
  `auth-pass-rates`/`volume` for the same underlying data). Any of these
  can be added on request if a real use case needs them.
- **RUA analytics tools' advanced query surface is simplified.** The
  `filters` object (an operator DSL: eq/ne/in/nin/gt/lt/etc, keyed by
  field) is accepted as a raw passthrough `dict` rather than fully typed —
  EasyDMARC's own API validates its shape and returns a structured error
  on a bad one. `group_by_fields`/`properties`/report-field enums ARE
  fully typed (56-value shared field taxonomy, verified against the spec).
- **Binary/file-download endpoints are out of scope** — failure reports'
  raw `.eml` file, single-attachment, and all-attachments-as-zip downloads
  return binary content this MCP (JSON-only tool returns) doesn't support.
  `easydmarc_get_failure_report`'s `downloadUrls` include option returns
  the URLs, but this MCP does not fetch them.
- **No tool has been individually smoke-tested against live data** — all
  24 are structurally correct (`tools/list` confirmed via the real MCP
  protocol, 16 unit tests passing, ruff-clean), but given the base-URL/
  route-availability question above, none should be assumed to work
  end-to-end until re-verified with a real account.
