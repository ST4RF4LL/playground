# 决策模型评估用例

当前收集方向：**代码片段是否存在漏洞**。

目前提供两个测试集合，每个集合均包含相同的 48 条代码片段、24 条正例和 24 条反例，以 Java 为主，兼顾 Python、C、JavaScript，覆盖 12 类 CWE。两个集合用于对比提问方式，共有 48 个独立片段。

| 集合 | 说明 | 可直接发送的请求 |
|---|---|---|
| `baseline` · 原始提问集合 | 保留原有请求；OWASP 样本判断目标 CWE，原创样本判断给定前提下是否存在漏洞 | [请求 JSONL](code_vulnerability/collections/baseline/inputs/requests.jsonl) |
| `cwe_specific` · 漏洞类型细化集合 | 全部限定具体 CWE，增加该类型的定义、成立条件和排除条件 | [请求 JSONL](code_vulnerability/collections/cwe_specific/inputs/requests.jsonl) |

在 Web 测试端的“测试集合”中切换。每个集合独立存放输入、标准答案、请求和清单，代码及样本 ID 保持一致，便于逐例比较；共享来源和构建脚本保留在 `code_vulnerability/sources/`、`code_vulnerability/scripts/`。

- [使用说明与评估口径](code_vulnerability/README.md)
- [原始集合索引（含答案）](code_vulnerability/collections/baseline/CATALOG.md)
- [细化集合索引（含答案）](code_vulnerability/collections/cwe_specific/CATALOG.md)
- [本地单页 Web 测试端](web/README.md)：配置完整 API 地址、可选 API Key 与模型名称，逐条或批量测试
- 每个集合的 `inputs/requests/` 包含 48 个独立请求 JSON，`inputs/requests.index.json` 对应 ID 和行号。
- 每个集合的 `inputs/cases.jsonl` 包含结构化代码与上下文，`inputs/prompts.jsonl` 提供兼容文本模型的提问。
- 每个集合的 `gold/answers.jsonl` 保存标准答案、依据和来源。

请求 body 已使用 `state/model/questions` 格式，默认模型名称为 `jev-latest`；可在页面中覆盖，或运行构建脚本的 `--model` 参数重新导出。请求不包含答案、ID 或评测元数据，ID 单独映射到文件。

只向被测模型发送请求 body 或所需输入文本；`gold/`、`sources/`、`scripts/`、用例索引和本说明属于评测侧资料。请求 ID 索引和集合信息用于本地关联结果，不发送给模型。构建及验证过程不调用真实模型，细化集合的效果需要使用相同模型、阈值和连接配置重新测试。
