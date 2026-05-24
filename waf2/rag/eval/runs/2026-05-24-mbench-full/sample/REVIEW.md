# M-Bench-Core Full Run Review (§10.3)

## 1. 6 张表全部出现

✓ Table 1 (Overall confusion), Table 2 (Per-family), Table 3 (Real vs synthetic),
Table 4 (Hard-neg vs template FP), Table 5 (Chain block-step), Table 6 (Per-subcategory).

## 2. 与 b0 / csic 对比

| 指标 | M-Bench-Core (sample 347) | B-0 (228 main) | 备注 |
|---|---|---|---|
| WAF1 union recall | **0.733** | 0.303 | M-Bench 50/150 是 char-injection,正中 WAF1 sqlInjection/xss/sensitiveFiles 等规则的覆盖范围;B-0 全是 PI,WAF1 only protocolAttacks 能命中,所以 B-0 WAF1 recall 低很多 |
| WAF2 RAG-on recall | **0.587** | 0.883 | M-Bench 50 chain 拉低 WAF2 (only 最后一步,recall=0.22);B-0 全是单步 PI,WAF2 LLM+RAG 强 |
| Dual recall | **0.833** | 0.899 | M-Bench 略低,因为 chain 25/50 = 50% 要求 step-1 早拦,WAF1/WAF2 都未触发;B-0 全单步,dual 接近 WAF2 上限 |
| Precision | **0.607** | "—" (precision=1 假设) | **M-Bench 首次能报真实 precision** — 这是项目的核心新增价值 |
| F1 | **0.702** | 0.899 (实为 recall) | 真实 F1 因为 FPR=0.411 存在 |
| FPR | **0.411** | 不可测 | **M-Bench 首次能报 FPR**;sample 中 hard-neg 占 64% 放大,1000 完整 benign WAF1 full 单层 FPR=0.228 (228/1000) |

**结论**:
- M-Bench-Core 与 B-0/CSIC **互补、不冲突** — 各自暴露不同维度的检测能力
- B-0 的 0.899 dual recall 报告了"在单步 PI 上的拦截率";M-Bench 的 0.833 dual recall 报告了"在 MCP-native 三家族 (char/PI/chain) 上的整体拦截率"
- M-Bench 首次让项目能在裁判面前展示**完整 confusion matrix**(TP+FN+FP+TN 四象限),而不仅是 recall

## 3. Hard-neg overblock callout 验证

Table 4 数据:

| layer | handcrafted FP/total | template FP/total | Δpp | callout 触发? |
|---|---|---|---|---|
| WAF1 (strict ∪ full) | 51/127 (40.2%) | 11/70 (15.7%) | **+24.4** | ✓ (≥10 触发) |
| WAF2 RAG ON | 48/127 (37.8%) | 6/70 (8.6%) | **+29.2** | ✓ |
| Dual | 66/127 (52.0%) | 15/70 (21.4%) | **+30.5** | ✓ |

**全 3 层触发 OVERBLOCK callout** ← 正常,handcrafted 段比 template 段 FP 高 24-30 pp,清晰反映"系统对形似攻击的正常请求过度敏感"。

Callout 触发逻辑工作正常 (report_mbench.py 阈值 +10 pp)。

## 4. 数字合理性 sanity checks

### Char injection 0.980 (49/50) ✓
- WAF1 sqlInjection/xss/shellInjection/pathTraversal 等模式已成熟,char-injection 几乎全 TP
- 1 条 FN 是 `mbc:attack:032` (`/var/lib/mysql/mysql.sock` 不在 sensitiveFiles 规则列表)

### PI 0.780 (39/50) — 中等 ✓
- 11 条 FN 集中在 RBAC bypass (6)、prompt_leak (3)、indirect_pi (1)、tool_poisoning (1)
- WAF 提升清单见 `mid-run-snapshot.md`

### Chain 0.740 (37/50) — 偏弱 ✓
- 13 条 FN 集中在 credential_theft chain (npmrc/kubeconfig/docker/gh tokens 路径未覆盖) 4 条 + supabase_lethal_trifecta 3 步链 3 条 + recon_then_exploit admin chain 2 条 + data_exfiltration bulk-read+POST 4 条
- 这是 WAF1 call-chain detector 的清晰差距,M-Bench 的核心价值就是测出这点

### Synthetic universe 0.667 vs Real 0.840 (Δ -17.4 pp) ✓
- 设计提到 "合成工具的检测难度可能高估或低估"(design.md Risks),Real > Synthetic 是预期方向
- 6 个合成 case 中 2 个漏(XXE billion-laughs 和 oauth_validator scope 都属于规则覆盖不全)

### Chain block-step recall 按步深递减 ✓
- step=1 (n=14): dual recall 0.929 — 早期拦截命中率高
- step=2 (n=27): dual recall 0.704
- step=3 (n=9): dual recall 0.556 — 需看完整链才能拦
- 符合 D2/D8 设计预期(早拦容易,深拦难)

## 5. 关键发现 highlights

1. **WAF1 调用链 detector 的盲区精确暴露**: 9 条 chain FN 给出具体修复路径(`mid-run-snapshot.md` G/H/I 节)
2. **RBAC args 字段识别完全缺失**: 6 条 rbac_bypass + 2 条 scope_escalation 全 FN — rbac.js 当前只看 header,不看 args 中的 role claim 字段
3. **WAF2 RAG-rescue 24 case**: 主要在 prompt_injection / xss 子类,说明 RAG KB 覆盖这些 pattern 有效
4. **Hard-neg vs Template FP rate 差 24-30 pp**: 系统的"过度敏感"程度首次量化

## 6. 报告结构对齐

- ✓ Fairness disclosures (6 条,含 sample disclosure 新增)
- ✓ Reproduction footer (含运行目录路径 + git hash)
- ✓ Wall-clock timing 表(本次首次加入)
- ✓ Interpretation section (overall + 3 family + chain block-step)

## 7. §10.3 决议

Review **通过**:
- 6 张表全部出现 ✓
- 数字合理(与设计预期、规则源码、b0 对比一致)✓
- Hard-neg overblock callout 正确触发(3/3 layer)✓
- WAF 提升信号清晰(`mid-run-snapshot.md` 给出 29 条 FN 的具体修复路径)✓

**已知限制**(由 §10.1 用户决议产生):
- Benign 是 197 sample 而非 1000 full(为快速反馈)
- WAF2 benign rag-off 未跑,merge 用 stub(主报告 dual 不依赖 rag-off,所以表里不报告该层)
- 后续 v2 需要补完整 1000 benign × WAF2 双 round 跑分(估 5-7h)

可以推进 §10.4 commit + §11 wrap-up。