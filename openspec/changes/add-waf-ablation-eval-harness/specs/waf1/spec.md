# waf1 spec delta — Stage independent enable switches

## ADDED Requirements

### Requirement: WAF1 SHALL expose an independent enable switch for the call-chain detector

The Stage 3 call-chain detector (`callChainTracker.check` invocation in `validateToolCall`) MUST be controllable independently of `setWaf1Enabled` and independently of any other Stage. The controlling field SHALL be `config.callChainEnabled` (boolean, default `true`).

When `callChainEnabled === false`:
- `callChainTracker.check(tool, args, context)` MUST NOT be invoked for that request
- The `chainResult` variable consumed downstream by Stage 5 (`runDetectors`) MUST default to `{ detected: false }` so that Stage 5 behaves as if no chain was detected
- The tracker's internal history MUST NOT be mutated by the skipped call (this guarantees that turning the switch back on mid-session does not produce stale chain hits)

When `callChainEnabled === true` (default): behavior MUST be identical to the pre-change implementation.

The switch MUST NOT alter Stage -1 (rate limit), Stage 0 (RBAC), Stage 1 (whitelist), Stage 2 (rules), Stage 4 (dynamic policy), or Stage 5 (detectors).

#### Scenario: Switch off — chain attack passes through

- **GIVEN** `callChainEnabled = false` and the data_exfiltration chain attack `mbc:chain:013` (list_orders(limit:1000) → http_request POST attacker.tld)
- **WHEN** the harness replays both steps via `evaluateChain`
- **THEN** neither step MUST be blocked by Stage 3
- **AND** if no other stage matches (no SQL injection, no sensitive file path, etc.), `validateToolCall` MUST return `{ allowed: true }` for both steps

#### Scenario: Switch on — chain attack blocked at expected step

- **GIVEN** `callChainEnabled = true` (default) and the same `mbc:chain:013` attack
- **WHEN** the harness replays both steps
- **THEN** step 2 (http_request POST) MUST be blocked
- **AND** the returned `category` MUST be `"callChain"`

#### Scenario: Toggling does not poison history

- **GIVEN** the harness ran 50 chain attacks with `callChainEnabled = false`
- **WHEN** the next case is run with `callChainEnabled = true` after `resetWaf1State()`
- **THEN** the chain tracker history MUST be empty
- **AND** the new case MUST be evaluated solely on its own step sequence

### Requirement: WAF1 SHALL expose an independent enable switch for the dynamic SQL policy

The Stage 4 dynamic SQL policy (`checkDynamicPolicy(tool, args)` invocation in `validateToolCall`) MUST be controllable independently of `setWaf1Enabled` and independently of any other Stage. The controlling field SHALL be `config.dynamicPolicyEnabled` (boolean, default `true`).

When `dynamicPolicyEnabled === false`:
- `checkDynamicPolicy(tool, args)` MUST NOT be invoked for that request
- `validateToolCall` MUST proceed directly to Stage 5 (`runDetectors`) regardless of the request shape (including `execute_sql` / `supabase__execute_sql` tools)

When `dynamicPolicyEnabled === true` (default): behavior MUST be identical to the pre-change implementation.

The switch MUST NOT alter the SUPABASE-related SQL helpers exported from `supabase-sql.js` (they remain importable and may still be called by the call-chain detector via `isSupabaseLeakWriteCall` etc., independent of this switch).

#### Scenario: Switch off — supabase sensitive read passes through

- **GIVEN** `dynamicPolicyEnabled = false` and a single-step call `tools/call(supabase__execute_sql, {query: "SELECT * FROM auth.users"})`
- **WHEN** `validateToolCall` runs
- **THEN** Stage 4 MUST NOT block the call
- **AND** if no other stage matches, `validateToolCall` MUST return `{ allowed: true }`

#### Scenario: Switch on — supabase sensitive read blocked

- **GIVEN** `dynamicPolicyEnabled = true` (default) and the same call
- **WHEN** `validateToolCall` runs
- **THEN** Stage 4 MUST block with `category = "dynamicPolicy"` and `reason` containing `"auth.users"`

#### Scenario: Switch off does not silently disable call-chain Stage 3

- **GIVEN** `dynamicPolicyEnabled = false` and `callChainEnabled = true`, and the supabase trifecta chain `mbc:chain:001` (read_public_table → execute_sql sensitive → execute_sql public write)
- **WHEN** all three steps run in sequence with the same `clientId`
- **THEN** Stage 4 MUST be skipped each step
- **AND** Stage 3 MUST still trigger on step 3 via the `supabase_lethal_trifecta` chain matcher
- **AND** the returned `category` MUST be `"supabaseCallChain"`

### Requirement: WAF1 SHALL expose an independent enable switch for the Stage 0.5 RBAC args role-claim tamper detector

The Stage 0.5 RBAC args role-claim tamper detector (`detectArgsRoleClaimTampering(args)` invocation in `validateToolCall`, introduced in commit `3a53a60`) MUST be controllable independently of `setWaf1Enabled` and independently of the legacy RBAC controller (`config.rbac.enabled`). The controlling field SHALL be `config.rbacArgsEnabled` (boolean, default `true`).

When `rbacArgsEnabled === false`:
- `detectArgsRoleClaimTampering(args)` MUST NOT be invoked for that request
- `validateToolCall` MUST proceed directly to Stage 1 (whitelist) even if `args` contains `actor_role`, `x_user_role`, `as_role`, `user_role`, `claim_override`, `bypass: true`, or `elevated: true`

When `rbacArgsEnabled === true` (default): behavior MUST match the post-`3a53a60` implementation — any of the role-claim fields present (or `bypass`/`elevated` strictly equal to `true`) MUST cause `validateToolCall` to return `{ allowed: false, error.category: "rbac" }`.

The switch MUST NOT alter the legacy Stage 0 RBAC controller (`rbacController.check`) — that remains gated by `config.rbac.enabled`.

#### Scenario: Switch off — RBAC args tamper attack passes through

- **GIVEN** `rbacArgsEnabled = false` and the RBAC bypass attack `mbc:attack:142` (`{id: 1, actor_role: "admin"}`)
- **WHEN** `validateToolCall` runs
- **THEN** Stage 0.5 MUST NOT match
- **AND** if no other stage matches (e.g., RBAC controller is disabled), `validateToolCall` MUST return `{ allowed: true }`

#### Scenario: Switch on — attack blocked with rbac category

- **GIVEN** `rbacArgsEnabled = true` (default) and the same attack
- **WHEN** `validateToolCall` runs
- **THEN** Stage 0.5 MUST block with `category = "rbac"` and `error.type = "RBAC_ARGS_TAMPER"`
- **AND** the `error.fields` array MUST contain `"actor_role"`

### Requirement: updateWaf1Config SHALL accept the three new enable fields and persist them to runtime config

The `updateWaf1Config(newConfig)` function (exported from `mcp-hub/src/waf1/index.js`) MUST accept `newConfig.waf1.callChainEnabled`, `newConfig.waf1.dynamicPolicyEnabled`, and `newConfig.waf1.rbacArgsEnabled` as optional boolean fields. Each field, when present, MUST be coerced to boolean (`!!value`) and assigned to the corresponding runtime `config.<fieldName>` slot. When a field is absent (i.e. `=== undefined`), the runtime value MUST remain unchanged.

The HTTP endpoint `POST /api/config/waf1` MUST pass these three fields through to `updateWaf1Config` unchanged, alongside the existing `enabled` and `rules` fields.

#### Scenario: API request sets all three switches in one call

- **WHEN** `POST /api/config/waf1` with body `{ waf1: { callChainEnabled: false, dynamicPolicyEnabled: false, rbacArgsEnabled: true } }` is received
- **THEN** all three runtime slots MUST be updated atomically before the response is returned
- **AND** the response MUST report success (HTTP 200)

#### Scenario: Partial update preserves untouched switches

- **GIVEN** `config.callChainEnabled = true`, `config.dynamicPolicyEnabled = true`, `config.rbacArgsEnabled = true`
- **WHEN** `POST /api/config/waf1` with body `{ waf1: { callChainEnabled: false } }` is received
- **THEN** `config.callChainEnabled` MUST become `false`
- **AND** `config.dynamicPolicyEnabled` and `config.rbacArgsEnabled` MUST remain `true`

#### Scenario: Boolean coercion for non-boolean inputs

- **WHEN** `POST /api/config/waf1` with body `{ waf1: { callChainEnabled: 0 } }` (truthy/falsy non-boolean)
- **THEN** `config.callChainEnabled` MUST become `false`
- **WHEN** the body is `{ waf1: { callChainEnabled: "yes" } }`
- **THEN** `config.callChainEnabled` MUST become `true`
