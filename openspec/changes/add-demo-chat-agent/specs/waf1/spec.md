## MODIFIED Requirements

### Requirement: 调用链检测器
调用链检测器 MUST 在 5 分钟时间窗口内追踪工具调用序列，识别"先读后写外发"等危险模式。检测 MUST 覆盖以下危险模式：
- `data_exfiltration`：先读取数据，再发送到外部
- `credential_theft`：先访问凭据，再发 HTTP 请求
- `recon_then_exploit`：先扫描/枚举，再注入/利用
- `supabase_lethal_trifecta`：读取用户可写内容后执行敏感 SQL 并写回公开表

`data_exfiltration` 模式的外发通道识别 MUST 包括 GitHub 写/外发工具：MUST 将 `create_or_update_file`、`create_pull_request`、`add_issue_comment`、`update_issue`、`push_files`、`edit_file`、`update_file`、`create_review`、`submit_review` 识别为外发写通道（与 `create_gist`/`create_issue`/`create_comment`/`create_file` 等同等对待）。

历史记录 MUST 保留最近 100 条调用。检测到危险调用链后 MUST 保留历史记录（**不清空**）——原设计清空历史以防级联告警，但会导致攻击者立即重试外发调用绕过（清空后无前置读记录）；保留历史使重试外发调用仍能被同一调用链触发拦截。拦截 MUST 返回 type `DETECTOR_BLOCKED`，category 沿用既有 `data_exfiltration`/`callChain` 分类（**不新增** `stats.js` 的 severity/MITRE 映射，复用既有 `data_exfiltration` 映射：severity=high，OWASP=LLM01:2025，MITRE=T1020 Exfiltration）。影响层：WAF1。

#### Scenario: GitHub 致命三角被调用链拦截（WAF 开）
- **WHEN** WAF1 已启用、调用链检测器已启用
- **AND** Agent 在 5 分钟内先调用 `server-github` 的 `get_file_contents`（或 `search_repositories`/`list_issues`）读取私有库内容
- **AND** 随后调用 `server-github` 的 `create_or_update_file` 将含 PII 的内容写入公开库
- **THEN** WAF1 MUST 检测到 `data_exfiltration` 模式
- **AND** MUST 拦截 `create_or_update_file` 调用，返回 HTTP 403 与 `{ error: "WAF1 拦截", reason, type: "DETECTOR_BLOCKED", category: "callChain" }`

#### Scenario: 通过 add_issue_comment / update_issue / push_files 外发同样被拦截
- **WHEN** Agent 先 `get_file_contents` 读私有库敏感数据
- **AND** 随后改用 `add_issue_comment`、`update_issue` 或 `push_files`（而非 `create_issue`/`create_or_update_file`）将数据外发到公开库
- **THEN** WAF1 MUST 仍检测到 `data_exfiltration` 模式并拦截（HTTP 403，type `DETECTOR_BLOCKED`，category `callChain`）
- **AND** 这些外发渠道 MUST NOT 因工具名不含 `create_` 而漏过

#### Scenario: 调用链检测器对 GitHub 写工具的识别不依赖 PII 格式
- **WHEN** 外发内容为西方格式 PII（姓名、地址、薪水），不含 email/信用卡/护照等 WAF1 PII 检测器可命中模式
- **AND** 满足"先读私有库→后 `create_or_update_file` 写公开库"调用链
- **THEN** 调用链检测器 MUST 仍触发拦截（识别信号为调用链模式，而非 PII 内容格式）

#### Scenario: 历史记录上限与清空
- **WHEN** 调用历史超过 100 条
- **THEN** MUST 移除最旧记录，保留最近 100 条

#### Scenario: 检测到链后保留历史，重试外发调用仍被拦截
- **WHEN** WAF1 已启用、调用链检测器已启用
- **AND** Agent 先 `get_file_contents` 读私有库敏感数据，后 `create_issue` 外发被调用链拦截
- **AND** Agent 随即重试 `create_issue`（同一 clientId、5 分钟窗口内）
- **THEN** 重试的 `create_issue` MUST 仍被 `data_exfiltration` 调用链拦截（HTTP 403，type `DETECTOR_BLOCKED`）
- **AND** 历史 MUST NOT 在首次拦截后被清空
