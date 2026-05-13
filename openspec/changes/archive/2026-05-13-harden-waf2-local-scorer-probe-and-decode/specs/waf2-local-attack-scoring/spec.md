## ADDED Requirements

### Requirement: Legacy web probe path scoring
WAF2 SHALL recognize a curated list of legacy IIS / FrontPage / CGI probe path patterns and score them at or above the static-block threshold so the risk router blocks the request without invoking RAG, local LLM, or ReAct.

The probe catalogue MUST cover two pattern families:
- Path **prefix / segment** patterns that indicate well-known legacy admin or CGI surfaces (for example `/_vti_pvt/`, `/_vti_bin/`, `/iisadmpwd/`, `/scripts/`, `/MSADC/`, `/cgi-bin/printenv`).
- Path **suffix** patterns that indicate include-file or backup probing (for example `.inc`, `.htr`, `.asa`, `.cmd`, `.bak`, `.old`, `.swp`), evaluated case-insensitively.

#### Scenario: IIS admin probe path is blocked statically
- **WHEN** a request path matches `/iisadmpwd/aexp.htr` (case-insensitive)
- **THEN** local scoring MUST mark it as `legacy_web_probe` with score ≥ `local_score_block_threshold`
- **AND** the risk router MUST route the request to `static_block`

#### Scenario: FrontPage extension probe path is blocked statically
- **WHEN** a request path contains `/_vti_pvt/` or `/_vti_bin/`
- **THEN** local scoring MUST mark it as `legacy_web_probe` with score ≥ `local_score_block_threshold`

#### Scenario: Include-file suffix probe is blocked statically
- **WHEN** a request path ends in `.inc`, `.htr`, `.asa`, `.cmd`, `.bak`, or `.old` (case-insensitive)
- **AND** the path is not in the probe-suffix whitelist
- **THEN** local scoring MUST mark it as `legacy_web_probe` with score ≥ `local_score_block_threshold`

#### Scenario: Whitelisted business resource is not flagged
- **WHEN** the path is registered in the probe-suffix whitelist
- **THEN** local scoring MUST NOT raise the legacy probe score
- **AND** the request MUST proceed through normal scoring

#### Scenario: Probe evidence is captured for reporting
- **WHEN** any legacy probe pattern matches
- **THEN** the detection record MUST include the matched pattern token in score evidence
- **AND** the route decision MUST be `static_block`

### Requirement: Double URL decode before pattern matching
WAF2 SHALL apply URL decoding up to two levels deep on request path, query string, and body before running existing SQLi / XSS / path-traversal pattern matchers. The scorer MUST evaluate both the original and the doubly-decoded forms, and MUST preserve original text for evidence and logging.

If the input still contains `%XX` patterns after two decode levels, WAF2 MUST add a small `multi_layer_encoding` anomaly score (below the static-block threshold) so the request flows into gray-zone analysis rather than being blocked outright.

#### Scenario: Doubly encoded SQL injection in body is detected
- **WHEN** a POST body field contains `%2527%2520OR%25201%253D1--` (double-encoded `' OR 1=1--`)
- **THEN** WAF2 MUST decode the field twice
- **AND** the SQLi pattern matcher MUST flag the decoded form
- **AND** score evidence MUST identify the offending field and decode depth

#### Scenario: Single-encoded SQLi previously missed is detected
- **WHEN** a body field contains `dni=%27OR%27a%3D%27a` (single-encoded `'OR'a='a`)
- **THEN** WAF2 MUST decode it
- **AND** the SQLi pattern matcher MUST flag `or 'a'='a` as a boolean-tautology indicator

#### Scenario: Doubly encoded path traversal is detected
- **WHEN** the path contains `%252e%252e%252fetc%252fpasswd`
- **THEN** WAF2 MUST decode it twice and trigger path-traversal scoring

#### Scenario: Residual encoding after two decode levels triggers anomaly
- **WHEN** after two URL decodes the string still contains `%[0-9a-f]{2}` (case-insensitive) patterns
- **THEN** WAF2 MUST add a `multi_layer_encoding` anomaly score < `local_score_block_threshold`
- **AND** the risk router MUST route the request to gray-zone analysis rather than static_block

#### Scenario: Original payload is preserved when decoding
- **WHEN** WAF2 decodes a request component for scoring
- **THEN** detection records MUST retain enough original payload context to explain the decision without losing the raw input

### Requirement: Header injection scoring
WAF2 SHALL include `Referer`, `Cookie`, and `User-Agent` request headers (after URL decoding up to two levels) as scoring inputs, applying the same SQLi / XSS / path-traversal pattern catalogue used for query and body. Additionally, the scorer MUST match `User-Agent` against a curated scanner-signature pattern set.

#### Scenario: SQLi in Referer is scored
- **WHEN** the `Referer` header decoded value contains a SQLi tautology pattern (for example `' OR 1=1--`)
- **THEN** local scoring MUST increase `sqli_score`
- **AND** evidence MUST indicate `Referer` as the originating field

#### Scenario: Scanner User-Agent is flagged
- **WHEN** the `User-Agent` header matches a known scanner signature (`sqlmap`, `nikto`, `nessus`, `acunetix`, `wpscan`)
- **THEN** local scoring MUST add a `scanner_signature` evidence entry with score ≈ 0.4
- **AND** the score MUST combine with other indicators to potentially cross the block threshold

#### Scenario: XSS payload in Cookie is scored
- **WHEN** the `Cookie` header decoded value contains `<script>`, `javascript:`, or an `onerror=` handler
- **THEN** local scoring MUST increase `xss_score`
- **AND** evidence MUST indicate `Cookie` as the originating field

#### Scenario: Clean headers do not introduce score
- **WHEN** `Referer`, `Cookie`, and `User-Agent` contain only typical browser values without attack indicators
- **THEN** local header scoring MUST contribute zero to the request score

#### Scenario: Headers are bounded for safety
- **WHEN** any of the scored headers exceeds a reasonable length limit (consistent with FastAPI default header size limits)
- **THEN** WAF2 MUST truncate or skip scoring for that header rather than allocate unbounded memory
