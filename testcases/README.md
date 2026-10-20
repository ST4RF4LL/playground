# 决策模型评估用例

当前评估方向：**代码漏洞识别**和 **Agent 行为安全**，两类任务分别存放、分别评分。

目前提供九个测试集合，共 1,056 条集合条目。其中原有五集合共 396 条：前两个共享 48 条代码片段（24 正 / 24 负），后三个共享同一批 100 个 CVE（全部正例），用于对比提问和上下文。新增四个公开基准子集共 660 条，分别评估下表所列方向。集合之间可能共享来源，不能把 1,056 条视为独立样本，也不提供混合总分。

| 新增集合 | 评估方向 | 规模 | 可直接发送的请求 |
|---|---|---:|---|
| `juliet_java_200` · Juliet Java | Java 基础漏洞语义与数据/控制流识别，10 类 CWE | 200 条，100 个正负对 | [请求 JSONL](code_vulnerability/collections/juliet_java_200/inputs/requests.jsonl) |
| `vul4j_60` · Vul4J | 真实 Java 项目中指定入口的漏洞与修复识别 | 60 条，30 个修复对 | [请求 JSONL](code_vulnerability/collections/vul4j_60/inputs/requests.jsonl) |
| `primevul_200` · PrimeVul | C/C++ 函数级目标 CWE 判别及修复区分 | 200 条，100 个修复对 | [请求 JSONL](code_vulnerability/collections/primevul_200/inputs/requests.jsonl) |
| `atbench_200` · ATBench | 完整 Agent 交互轨迹的行为安全 | 200 条，安全/不安全各 100 | [请求 JSONL](agent_safety/collections/atbench_200/inputs/requests.jsonl) |

前三套新集合的负例仅表示**给定范围内没有目标 CWE**；ATBench 判断整段轨迹的行为，使用独立的安全标签。公开来源标签、静态审阅和导出校验不等于本地已动态复现所有漏洞。来源、版本、转换和限制分别见 [Juliet](code_vulnerability/sources/juliet_java/README.md)、[Vul4J](code_vulnerability/sources/vul4j/README.md)、[PrimeVul](code_vulnerability/sources/primevul/README.md)、[ATBench](agent_safety/sources/atbench/README.md)。

ATBench 中形似凭据的值已一致替换为不可用的合成标识，保留轨迹结构、跨消息引用关系及上游标签；评估时按原场景中的有效凭据理解。转换规则、原始来源哈希和脱敏统计保存在来源目录。

原有集合：

| 集合 | 说明 | 可直接发送的请求 |
|---|---|---|
| `baseline` · 原始提问集合 | 保留原有请求；OWASP 样本判断目标 CWE，原创样本判断给定前提下是否存在漏洞 | [请求 JSONL](code_vulnerability/collections/baseline/inputs/requests.jsonl) |
| `cwe_specific` · 漏洞类型细化集合 | 全部限定具体 CWE，增加该类型的定义、成立条件和排除条件 | [请求 JSONL](code_vulnerability/collections/cwe_specific/inputs/requests.jsonl) |
| `cve_random_100` · 知识库 CVE 随机 100 | 100 个不同 CVE，仅正样本，主要评估检出率与漏报 | [请求 JSONL](code_vulnerability/collections/cve_random_100/inputs/requests.jsonl) |
| `cve_cwe_specific_100` · CVE 100 · CWE 判据细化 | 相同代码、前提、ID 和标签，仅补齐 30 类 CWE 的具体判据 | [请求 JSONL](code_vulnerability/collections/cve_cwe_specific_100/inputs/requests.jsonl) |
| `cve_focused_100` · CVE 100 · 判据细化＋聚焦代码 | 沿用详细判据，保留候选位置相关完整函数与依赖；无法可靠裁剪时保留原文件 | [请求 JSONL](code_vulnerability/collections/cve_focused_100/inputs/requests.jsonl) |

在 Web 测试端的“测试集合”中切换，页面会显示当前集合的评估方向。代码集合位于 `code_vulnerability/collections/<ID>/`，Agent 集合位于 `agent_safety/collections/<ID>/`；每个集合独立保存输入、标准答案、请求和清单。新增集合后重启服务。切换前请导出当前结果。

- [使用说明与评估口径](code_vulnerability/README.md)
- [原始集合索引（含答案）](code_vulnerability/collections/baseline/CATALOG.md)
- [细化集合索引（含答案）](code_vulnerability/collections/cwe_specific/CATALOG.md)
- [100 CVE 索引（含答案）](code_vulnerability/collections/cve_random_100/CATALOG.md) · [抽样与证据说明](code_vulnerability/sources/knowledge_workflow/README.md)
- [本地单页 Web 测试端](web/README.md)：配置完整 API 地址、可选 API Key 与模型名称，逐条或批量测试
- 每个集合的 `inputs/requests/` 包含与集合用例数一致的独立请求 JSON，`inputs/requests.index.json` 对应 ID 和行号。
- 每个集合的 `inputs/cases.jsonl` 包含结构化输入；原有五集合另有 `inputs/prompts.jsonl`，新增四集合以原生请求 body 为入口。
- 每个集合的 `gold/answers.jsonl` 保存标准答案、依据和来源。

请求 body 使用 `state/model/questions` 格式，默认模型名称为 `jev-latest`；可在页面中覆盖，或运行构建脚本的 `--model` 参数重新导出。代码任务使用 `has_vulnerability`，Agent 行为任务使用 `has_unsafe_behavior`，高分分别表示有漏洞或不安全行为。请求不包含标准答案、ID 或评测元数据，ID 单独映射到文件。所有新请求通过 256K 保守预算检查，无静默截断。

离线重建新增四集合（读取已归档输入，不联网、不执行样本）：

```bash
python3 /Users/wh4lter/Workspace/playground/testcases/code_vulnerability/scripts/build_public_collections.py
python3 /Users/wh4lter/Workspace/playground/testcases/code_vulnerability/scripts/build_public_collections.py --validate-only
```

可通过 `--collection` 只构建一套，通过 `--model` 指定导出模型。进一步从原始来源重建时，使用各来源说明列出的 `import_*.py`。三个代码集合同时报告单条准确率和“配对两侧均答对”的比例；ATBench 按完整轨迹评分，并按风险类别分组。

只向被测模型发送请求 body 或所需输入文本；`gold/`、`sources/`、`scripts/`、用例索引和本说明属于评测侧资料。请求 ID 索引和集合信息用于本地关联结果，不发送给模型。构建及验证过程不调用真实模型，细化集合的效果需要使用相同模型、阈值和连接配置重新测试。
