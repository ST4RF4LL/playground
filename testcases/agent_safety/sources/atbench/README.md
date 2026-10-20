# ATBench：完整 Agent 轨迹安全

来源：[官方数据](https://huggingface.co/datasets/AI45Research/ATBench)，固定 revision
`4476ef92ed8f85c8d58d8a5b9dfdf55aa7893138`，配置 `ATBench`、`test` split。
数据卡声明 Apache-2.0；本目录保留发布数据卡与许可证文本。

官方 1,000 条中有 503 安全、497 不安全。本子集用 seed `20261020`，
先排除完整请求超出平台 256K 保守预算的记录，再分别在两种标签内部按 `risk_source`
分桶打乱，轮流从各桶取样，选 100 安全、100 不安全。超预算记录整条排除，不截断工具定义或轨迹。
因此不是对原数据风险分布的无偏随机估计。抽样始终使用脱敏前原文和原有上下文，
因此以下凭据替换不会改变选中 ID、标签或分布。`SOURCE_LOCK.json` 记录完整文件哈希、选中 ID 和分布。
按此请求模板和预算共排除 14 条超预算源记录，其 ID 也记录在锁文件中。
`redacted_selected.json` 归档经过一致凭据脱敏的选中记录，可离线重建；
不分发含原始凭据格式的旧 `raw_selected.json`，也不保存原值与合成标识的映射。
未运行其中任何工具、URL 或代码，未联网验证凭据。

本子集是 **ATBench 的凭据脱敏派生版本**，并非逐字原文。导入器识别提供商密钥格式、
JWT、Slack/Discord webhook 的秘密路径部分、连接 URI 密码，以及明确凭据字段中的
较长凭据形状字符串。它在所有字符串值（包括轨迹、工具描述和 gold 来源注释）中统一替换
相同完整字面值为 `SYNTHETIC_CREDENTIAL_<摘要>`，保留重复引用的相等关系。
字典字段名、数组结构、交互顺序、官方 label 和非字符串值保持不变；
短示例值和普通风险描述词不会按通用凭据规则替换。规则及每条记录替换次数记在锁文件中。
统一评估上下文明确要求按原场景中的有效凭据判断授权、泄露和滥用，
不能因展示的是合成标识就视为没有风险。该变换可能影响模型表现，成绩应注明为脱敏版本。

仅 `tool_used`、`contents` 与统一评估上下文送入模型。保持完整嵌套交互次序，
不截断工具定义或轨迹；仅做上述凭据替换。官方 label、经过同样凭据替换的 reason、
三类诊断标签仅留在 gold。
数据卡说明细分类别会出现在安全样本中；抽查也发现某些安全样本的 reason
仍描述攻击风险，故保留它为 `source_reason`，不以该说明覆盖官方二元 label。
这是保留上游标注的评测子集，未宣称完成全部标签的独立人工复核。

评估问题为 `has_unsafe_behavior`，输出 `unsafe` / `safe`，不使用代码漏洞标签。
它测试完整轨迹风险判断，不是单步工具授权，也不等于端到端 Agent 攻击成功率。
数据由合成流程生成并由上游人工审核，与真实生产流量应分别报告。
保持这 200 条为固定测试集；不要用同一批结果反复调提示后声称独立泛化效果。

离线重建：

```sh
python3 testcases/code_vulnerability/scripts/import_atbench.py
python3 testcases/code_vulnerability/scripts/import_atbench.py --check
python3 testcases/code_vulnerability/scripts/build_public_collections.py --collection atbench_200
```

无参数重建前先验证已归档脱敏记录的哈希；`--check` 比较脱敏记录、派生输入和锁文件，不写文件。
锁文件同时保存官方完整文件 SHA-256、脱敏前选样文件 SHA-256、
每条脱敏前/后记录的规范 JSON SHA-256，以及脱敏规则版本和数量；不保存原始秘密映射。
若持有固定版本的完整官方 `test.json`，可通过
`--source /absolute/path/test.json --check` 重新验证完整抽样及脱敏过程；
先核对官方完整文件 SHA-256，再按原文抽样，最后脱敏，不执行数据内动作。
完整原始来源只应放在仓库外的临时目录，不应提交。
