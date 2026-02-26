## MODIFIED Requirements

### Requirement: 管理后台

层级：Dashboard

配置 Tab 内所有 `.config-section` 区块 MUST 支持手风琴收缩/展开交互。每个 section header 可点击切换内容区域的可见性。

各 section 默认状态 MUST 为：

| Section | data-section-id | 默认状态 |
|---------|-----------------|----------|
| 防护模式 | `mode` | 展开 |
| 快速配置 - 完整防护 | `config-full` | 展开 |
| 快速配置 - 轻量防护 | `config-lite` | 展开 |
| 配置指引 | `guide` | 收起 |
| WAF 规则开关 | `waf-rules` | 收起 |
| 数据管理 | `data-mgmt` | 收起 |

#### Scenario: 点击收起展开的 section
- **WHEN** 用户点击已展开 section 的 header
- **THEN** 该 section 的 `.config-section-body` 以 `max-height` + `opacity` 过渡动画收起至不可见
- **AND** header 右侧 chevron 旋转至 −90°

#### Scenario: 点击展开收起的 section
- **WHEN** 用户点击已收起 section 的 header
- **THEN** 该 section 的 `.config-section-body` 以过渡动画展开
- **AND** header 右侧 chevron 旋转回 0°

#### Scenario: header hover 反馈
- **WHEN** 用户鼠标悬停在 section header 上
- **THEN** header 背景色变为 `var(--bg-surface-2)`
- **AND** cursor 显示为 pointer

#### Scenario: 页面加载默认状态
- **WHEN** 配置 Tab 首次渲染
- **THEN** 防护模式和当前模式对应的快速配置 section 默认展开
- **AND** 配置指引、WAF 规则开关、数据管理 section 默认收起

#### Scenario: 配置指引统一机制
- **WHEN** 配置指引 section 使用新的统一手风琴机制
- **THEN** 旧的 `toggleAccordion('config-guide')` 硬编码逻辑 MUST 被移除
- **AND** 行为与其他 section 一致（class 驱动，非 inline style）
