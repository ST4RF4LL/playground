# 决策模型评估用例

当前评估方向：**代码漏洞识别**和 **Agent 行为安全**，两类任务分别存放、分别评分。

目前提供十三个测试集合，共 4,136 条集合条目。其中原有五集合共 396 条：前两个共享 48 条代码片段（24 正 / 24 负），后三个共享同一批 100 个 CVE（全部正例），用于对比提问和上下文。八个公开基准子集共 3,740 条，分别评估下表所列方向。集合之间可能共享来源，不能把 4,136 条视为独立样本，也不提供混合总分。

| 公开基准集合 | 评估方向 | 规模 | 可直接发送的请求 |
|---|---|---:|---|
| `juliet_java_1000` · Juliet Java | Java 基础漏洞语义与数据/控制流识别，10 类 CWE | 1,000 条，500 个正负对 | [请求 JSONL](code_vulnerability/collections/juliet_java_1000/inputs/requests.jsonl) |
| `vul4j_60` · Vul4J | 真实 Java 项目中指定入口的漏洞与修复识别 | 60 条，30 个修复对 | [请求 JSONL](code_vulnerability/collections/vul4j_60/inputs/requests.jsonl) |
| `primevul_200` · PrimeVul | C/C++ 函数级目标 CWE 判别及修复区分 | 200 条，100 个修复对 | [请求 JSONL](code_vulnerability/collections/primevul_200/inputs/requests.jsonl) |
| `atbench_200` · ATBench | 完整 Agent 交互轨迹的行为安全 | 200 条，安全/不安全各 100 | [请求 JSONL](agent_safety/collections/atbench_200/inputs/requests.jsonl) |
| `owasp_java_web_180` · OWASP Java Web | Java Web 数据流与密码算法、散列、Cookie 配置判定，9 类 CWE | 180 条，正负各 90，不配对 | [请求 JSONL](code_vulnerability/collections/owasp_java_web_180/inputs/requests.jsonl) |
| `cweval_100` · CWEval | Python / JavaScript / Go 相同功能契约下的安全实现对照 | 100 条，50 个正负对 | [请求 JSONL](code_vulnerability/collections/cweval_100/inputs/requests.jsonl) |
| `devign_test_1000` · Devign / CodeXGLUE | C 函数级漏洞二分类，传统 ML 基准对照，不指定 CWE | 1,000 条，正负各 500，不配对 | [请求 JSONL](code_vulnerability/collections/devign_test_1000/inputs/requests.jsonl) |
| `secvuleval_paired_1000` · SecVulEval | C/C++ 真实函数的目标 CWE 与修复识别，20 类 CWE | 1,000 条，500 个正负对 | [请求 JSONL](code_vulnerability/collections/secvuleval_paired_1000/inputs/requests.jsonl) |

负例含义以判定范围为准：指定 CWE 的集合只排除该目标；Devign 沿用上游函数级二分类，不提供 CWE；ATBench 判断整段轨迹的行为，使用独立的安全标签。公开来源标签、静态审阅和导出校验不等于本地已动态复现所有漏洞。来源、版本、转换和限制分别见 [Juliet](code_vulnerability/sources/juliet_java/README.md)、[Vul4J](code_vulnerability/sources/vul4j/README.md)、[PrimeVul](code_vulnerability/sources/primevul/README.md)、[ATBench](agent_safety/sources/atbench/README.md)、[OWASP Java Web](code_vulnerability/sources/owasp_java_web/README.md)、[CWEval](code_vulnerability/sources/cweval/README.md)、[Devign](code_vulnerability/sources/devign/README.md)、[SecVulEval](code_vulnerability/sources/secvuleval/README.md)。

Juliet 已从 200 条扩至 1,000 条，集合 ID 更新为 `juliet_java_1000`，原 200 条保留在其中。旧 200 条结果仍属于旧版本，不与新批次混合评分。

此前新增 OWASP Java Web 和 CWEval 共 280 条：前者排除了原 24 个 OWASP 样本，但模板仍同源；后者由安全编码任务的参考实现转为分类配对，排除了有明显标签争议的任务。两套完整请求额外检查 compact UTF-8 body 不超过 64 KiB，不裁切代码；平台整体 256K 预算保持原样。

Devign 与 SecVulEval 已分别从 200 条扩充至 1,000 条，共 2,000 条，原有 200 条的 ID、输入与标签保持不变，分别作为传统函数分类对照和真实函数修复对照。保留固定来源与原标签，排除现有集合的提交/可执行 token 重叠；SecVulEval 额外排除重复 CVE。均为独立派生子集，不能直接套用原论文分数，也未进行独立动态复现。两套请求同样低于 64 KiB。

ATBench 中形似凭据的值已一致替换为不可用的合成标识，保留轨迹结构、跨消息引用关系及上游标签；评估时按原场景中的有效凭据理解。转换规则、原始来源哈希和脱敏统计保存在来源目录。

原有集合：

| 集合 | 说明 | 可直接发送的请求 |
|---|---|---|
| `baseline` · 原始提问集合 | 保留原有请求；OWASP 样本判断目标 CWE，原创样本判断给定前提下是否存在漏洞 | [请求 JSONL](code_vulnerability/collections/baseline/inputs/requests.jsonl) |
| `cwe_specific` · 漏洞类型细化集合 | 全部限定具体 CWE，增加该类型的定义、成立条件和排除条件 | [请求 JSONL](code_vulnerability/collections/cwe_specific/inputs/requests.jsonl) |
| `cve_random_100` · 知识库 CVE 随机 100 | 100 个不同 CVE，仅正样本，主要评估检出率与漏报 | [请求 JSONL](code_vulnerability/collections/cve_random_100/inputs/requests.jsonl) |
| `cve_cwe_specific_100` · CVE 100 · CWE 判据细化 | 相同代码、前提、ID 和标签，仅补齐 30 类 CWE 的具体判据 | [请求 JSONL](code_vulnerability/collections/cve_cwe_specific_100/inputs/requests.jsonl) |
| `cve_focused_100` · CVE 100 · 判据细化＋聚焦代码 | 沿用详细判据，保留候选位置相关完整函数与依赖；无法可靠裁剪时保留原文件 | [请求 JSONL](code_vulnerability/collections/cve_focused_100/inputs/requests.jsonl) |

在 Web 测试端切换浏览集合，或多选集合顺序批量执行；页面会显示各集合的评估方向。代码集合位于 `code_vulnerability/collections/<ID>/`，Agent 集合位于 `agent_safety/collections/<ID>/`；每个集合独立保存输入、标准答案、请求和清单。新增集合后重启服务。每次运行自动保存独立汇总历史到 `testcases/results/history.json`（不跟踪到 Git），页面可下载全部历史 JSON；切换前可手动导出需要保留的逐条详情。

- [使用说明与评估口径](code_vulnerability/README.md)
- [原始集合索引（含答案）](code_vulnerability/collections/baseline/CATALOG.md)
- [细化集合索引（含答案）](code_vulnerability/collections/cwe_specific/CATALOG.md)
- [100 CVE 索引（含答案）](code_vulnerability/collections/cve_random_100/CATALOG.md) · [抽样与证据说明](code_vulnerability/sources/knowledge_workflow/README.md)
- [本地单页 Web 测试端](web/README.md)：配置完整 API 地址、可选 API Key 与模型名称，逐条或批量测试
- 每个集合的 `inputs/requests/` 包含与集合用例数一致的独立请求 JSON，`inputs/requests.index.json` 对应 ID 和行号。
- 每个集合的 `inputs/cases.jsonl` 包含结构化输入；原有五集合另有 `inputs/prompts.jsonl`，公开基准集合以原生请求 body 为入口。
- 每个集合的 `gold/answers.jsonl` 保存标准答案、依据和来源。

请求 body 使用 `state/model/questions` 格式，默认模型名称为 `jev-latest`；可在页面中覆盖，或运行构建脚本的 `--model` 参数重新导出。代码任务使用 `has_vulnerability`，Agent 行为任务使用 `has_unsafe_behavior`，高分分别表示有漏洞或不安全行为。请求不包含标准答案、ID 或评测元数据，ID 单独映射到文件。所有新请求通过 256K 保守预算检查，无静默截断。

离线重建八个公开基准集合（读取已归档输入，不联网、不执行样本）：

```bash
python3 /Users/wh4lter/Workspace/playground/testcases/code_vulnerability/scripts/build_public_collections.py
python3 /Users/wh4lter/Workspace/playground/testcases/code_vulnerability/scripts/build_public_collections.py --validate-only
```

可通过 `--collection` 只构建一套，通过 `--model` 指定导出模型。进一步从原始来源重建时，使用各来源说明列出的 `import_*.py`。Juliet、Vul4J、PrimeVul、CWEval、SecVulEval 同时报告单条准确率和“配对两侧均答对”的比例；OWASP Java Web、Devign 无修复配对；ATBench 按完整轨迹评分，并按风险类别分组。

只向被测模型发送请求 body 或所需输入文本；`gold/`、`sources/`、`scripts/`、用例索引和本说明属于评测侧资料。请求 ID 索引和集合信息用于本地关联结果，不发送给模型。构建及验证过程不调用真实模型，细化集合的效果需要使用相同模型、阈值和连接配置重新测试。
