# easydmarc-mcp

MCP server for **EasyDMARC** — an email authentication / anti-phishing
platform. EasyDMARC monitors a domain's DMARC/SPF/DKIM/BIMI/MTA-STS/TLS-RPT
DNS setup and aggregates the DMARC reports mailbox providers send back, so
an MSP can see whether a client domain is protected against spoofing and
fix misconfigurations. This server exposes an MVP subset of EasyDMARC's
public partner/MSP-tenant REST API as MCP tools.

## Overview

- Stateless HTTP service. No credentials are ever persisted — each request
  supplies its own client_id/client_secret via headers, used only to
  exchange for a bearer token for the lifetime of that single request.
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

EasyDMARC's public API authenticates with a bearer access token
(`Authorization: Bearer <token>`), but that token comes from
`POST /auth/token` exchanging a long-lived **client_id/client_secret**
pair and is only valid for `expires_in` seconds (300 in EasyDMARC's own
documented example) — `refresh_expires_in` is documented as *always 0*,
i.e. there is no refresh, only re-requesting a new token.

That doesn't fit a platform where an operator fills in credentials once and
expects them to keep working: a ~5-minute token saved as "the credential"
goes stale minutes after setup and every tool call 401s from then on. So
this server accepts the **client_id/client_secret pair** instead (the
credential that's actually long-lived) and does its own token exchange
internally, once per API call, discarding the token immediately after —
see `src/easydmarc_mcp/api_client.py` for the exact exchange and why it's
never cached.

### HEADER 授权参数说明

| Header | 类型 | 是否必填 | 默认值 | 枚举值 | 字段描述 | Example |
|---|---|---|---|---|---|---|
| `X-EasyDMARC-Client-Id` | string | 是 | 无 | 无 | EasyDMARC Account Console 里的 API Client ID（长期凭据） | `api.JRd7Z4qk...` |
| `X-EasyDMARC-Client-Secret` | string | 是 | 无 | 无 | 对应的 API Client Secret（长期凭据） | `Szt832kHiY...` |

Missing either header returns `401`:
```json
{
  "error": "Missing credentials",
  "message": "This server requires the X-EasyDMARC-Client-Id, X-EasyDMARC-Client-Secret headers",
  "required_headers": ["X-EasyDMARC-Client-Id", "X-EasyDMARC-Client-Secret"],
  "optional_headers": []
}
```

**认证机制**：本服务收到这两个凭据后，自己去调 `POST https://api2.easydmarc.com/auth/token`（表单参数 `client_id`/`client_secret`，注意 token 端点的 host 跟业务 API 的 host 不是同一个——这是 EasyDMARC 官方 OpenAPI 规范里 `/auth/token` 路径的 `servers` 覆盖字段明确写的，不是猜的）换出真正的 bearer token，再拿这个 token 去调实际接口。**每次调用都重新换一次 token，从不缓存**——多租户场景下缓存 token 容易在并发请求间串号，多一次 HTTP 往返换取完全无状态是划算的取舍（`oitvoip-mcp`/`ingrammicro-mcp`/`action1-mcp` 都是这个模式）。

## Environment Variables

| Variable | 类型 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `MCP_TRANSPORT` | string | 否 | `stdio` | `http`（生产）或 `stdio`（本地开发） |
| `MCP_HTTP_PORT` | int | 否 | `8080` | HTTP 监听端口 |
| `MCP_HTTP_HOST` | string | 否 | `0.0.0.0` | HTTP 监听地址 |
| `AUTH_MODE` | string | 否 | `gateway` | `gateway`（生产，逐请求从 Header 取凭据）或 `env`（仅本地开发，共享单一凭据） |
| `EASYDMARC_CLIENT_ID` | string | 仅 `env` 模式必填 | 无 | 共享 Client ID（仅本地开发） |
| `EASYDMARC_CLIENT_SECRET` | string | 仅 `env` 模式必填 | 无 | 共享 Client Secret（仅本地开发） |
| `EASYDMARC_BASE_URL` | string | 否 | `https://api.easydmarc.com` | EasyDMARC 业务 API 基础 URL（token 交换固定走 `api2.easydmarc.com`，不受此项影响） |
| `EASYDMARC_CLIENT_ID_HEADER` | string | 否 | `X-EasyDMARC-Client-Id` | gateway 模式下承载 Client ID 的 Header 名 |
| `EASYDMARC_CLIENT_SECRET_HEADER` | string | 否 | `X-EasyDMARC-Client-Secret` | gateway 模式下承载 Client Secret 的 Header 名 |

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
  -H "X-EasyDMARC-Client-Id: <your-easydmarc-client-id>" \
  -H "X-EasyDMARC-Client-Secret: <your-easydmarc-client-secret>" \
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

- **Auth model changed 2026-09-02, partially re-verified live.** This
  server originally accepted an already-issued bearer token per request
  (`X-EasyDMARC-Token`, forwarded verbatim). That was found to be
  unworkable in real use: EasyDMARC's tokens expire in ~5 minutes with no
  refresh (`refresh_expires_in` is documented as always `0`), while the
  platform's credential model is "operator fills in credentials once,
  reused indefinitely" — every deployment would start failing every tool
  call with 401 a few minutes after setup. Fixed by accepting the
  long-lived `client_id`/`client_secret` pair instead and having
  `EasyDMARCClient` exchange it for a fresh token on every call (see
  Authentication above and `api_client.py`'s docstring). The `/auth/token`
  request/response shape and its `api2.easydmarc.com` host come from
  EasyDMARC's own OpenAPI spec (`AuthTokenRequest`/`AuthTokenResponse`, the
  `servers` override on that one path). **Partially live-verified
  already**: running this server for real and calling a tool with a dummy
  client_id/secret produced a genuine network round trip to
  `https://api2.easydmarc.com/auth/token`, which answered with a real
  `401 Unauthorized` (confirmed in both the tool's error envelope and the
  server's own httpx request log) — proving host/path/form-encoding are
  all correct and the endpoint is live, unlike the 404s the original
  investigation got from every path under `api.easydmarc.com`. What's
  still unconfirmed is the *success* path: no real client_id/client_secret
  was available to verify `_login()` returns a usable `access_token` and
  that a subsequent business-API call succeeds with it.
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
