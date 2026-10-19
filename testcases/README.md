# 决策模型评估用例

当前收集方向：**代码片段是否存在漏洞**。

第一批共 48 条，24 条有漏洞、24 条在指定判定范围内无漏洞；以 Java 为主，另含 Python、C、JavaScript。覆盖 12 类 CWE，包含公开基准样本和原创成对对照。

- [使用说明与评估口径](code_vulnerability/README.md)
- [用例索引（含答案）](code_vulnerability/CATALOG.md)
- [本地单页 Web 测试端](web/README.md)：配置完整 API 地址、可选 API Key 与模型名称，逐条或批量测试
- [可直接发送的 System One 请求 JSONL](code_vulnerability/inputs/requests.jsonl)：每行一个 POST body
- [48 个独立请求 JSON 文件](code_vulnerability/inputs/requests/)
- [请求 ID / 行号 / 文件索引](code_vulnerability/inputs/requests.index.json)
- [兼容文本模型的 Prompt 模板](code_vulnerability/inputs/prompts.jsonl)
- [结构化代码与上下文](code_vulnerability/inputs/cases.jsonl)
- [标准答案、依据和来源](code_vulnerability/gold/answers.jsonl)

请求 body 已使用 `state/model/questions` 格式，默认模型名称为 `jev-latest`；可在页面中覆盖，或运行构建脚本的 `--model` 参数重新导出。请求不包含答案、ID 或评测元数据，ID 单独映射到文件。

只向被测模型发送请求 body 或所需输入文本；`gold/`、`sources/`、`scripts/`、用例索引和本说明属于评测侧资料。请求 ID 索引用于本地关联结果，也不发送给模型。尚未调用真实模型，未产生真实模型准确率。
