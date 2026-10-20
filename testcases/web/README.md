# Decision Lab · 单页漏洞判定测试端

启动后访问 **http://127.0.0.1:8765**：

```bash
python3 /Users/wh4lter/Workspace/playground/testcases/web/server.py
```

需要 Python 3.10+，只用标准库，不需要安装前端依赖。可用 `--port 8766` 改端口。按 Ctrl+C 停止服务。

Windows 下可在仓库根目录运行 `python testcases/web/server.py`。数据文件统一按 UTF-8 读写，不依赖系统默认编码。如果使用旧版本遇到 `'gbk' codec can't decode`，可临时运行 `python -X utf8 testcases/web/server.py`，或更新到修复版本后正常启动。

## 使用

先在页面上方选择**测试集合**：`baseline` 保留原始提问，`cwe_specific` 使用相同 48 条代码、ID 和标签，统一判断某个具体 CWE，并增加该类别的成立及排除条件。`cve_random_100` 是从本地知识库抽取的 100 个不同 CVE，仅含漏洞版本，主要看检出率和漏报，不能用于估计误报率。新增集合后需重启服务。切换集合会清空当前页面的结果和指标，请先导出需要保留的结果；API、模型、密钥、阈值、超时与代理配置会保留。运行期间不能切换集合。

1. 填写 **Decision-model API** 完整地址，例如 `https://api.typesafe.ai/v1/systemone` 或自建服务的 `http://127.0.0.1:8000/v1/systemone/`。程序原样发送，不额外拼接路径。
2. 填写 **模型名称**，默认 `jev-latest`。**API Key 可选**：填写后使用 `Authorization: Bearer ...`；留空不发送该请求头。TypeSafe 官方云服务需要密钥，允许匿名的兼容服务可以留空。
3. 高级设置中的**代理模式默认直连**，不读取环境变量或操作系统的代理设置，适合直接访问公司内网 API。需要代理时，选择“使用环境 / 系统代理”：HTTP 接口读取 `http_proxy/HTTP_PROXY`，HTTPS 接口读取 `https_proxy/HTTPS_PROXY`，并遵循 `no_proxy/NO_PROXY`；没有环境代理配置时，Python 还可能使用操作系统代理设置。
4. 点击案例查看实际请求 body，再单条试跑或按当前筛选批量运行。高级设置还可调整阈值（默认 0.5）及连接/读取超时（默认 60 秒）。
5. 下载请求 JSONL，或导出本批结果和指标。结果 JSONL 可交给已有 `code_vulnerability/scripts/score.py` 评分。

上下文预算固定按 **256K（262,144 token）** 处理，高级设置显示选中请求的保守估算。估算方法是对实际 `state` 与 `questions` 的 JSON 统计 UTF-8 字节数，再加 **1,024** 的固定 schema 余量；这是估算上界，不是精确 tokenizer 计数，也不保证覆盖未知的服务端提示模板。不会把字符数当成 token 数。超出估算预算的请求在本地明确记为错误，既不发送也不静默截断；预算元数据保留在结果导出中，不加入模型 body。仍保留独立的 **2 MiB** 本地 HTTP 请求体及上游响应大小限制；它们是传输限制，不是上下文窗口。本工具没有另设 64 KiB 请求限制。

修改 API 地址和模型名称后，点击连接配置右上角的“保存为默认”。当前浏览器会记住这两项，下次打开或刷新时自动恢复；保存按测试端的访问地址和端口区分。API Key 仍只保留在本次页面内存中。

测试集合从 `../code_vulnerability/collections/<集合 ID>/` 自动加载，每个目录保存独立的 `inputs/`、`gold/` 和 `manifest.json`。界面展示标准答案用于对照，但实际发往模型的 body 仅含 `state/model/questions`。`state` 只包含语言、判定范围、目标 CWE、上下文和代码。集合 ID、样本 ID、标题、标签、答案解释及来源不会发送给模型。

请求示意（真实请求中的 state 包含完整上下文和代码）：

```json
{
  "state": {"language":"java","scope":"target_cwe_only","target_cwe":"CWE-89","context":"…","code":"…"},
  "model": "jev-latest",
  "questions": {
    "has_vulnerability": {
      "type": "noul",
      "instructions": "根据给定上下文与判定范围，判断是否存在漏洞。",
      "criteria": {"true":"存在可达的漏洞路径。","false":"给定前提下不存在所判定的漏洞。"}
    }
  }
}
```

真实 body 以页面预览或 `code_vulnerability/collections/<集合 ID>/inputs/requests/<id>.json` 为准。它使用决策模型的原生问题协议，不发送通用聊天接口的 `messages` 或要求模型输出 JSON 的 prompt。细化集合的同一 CWE 共用同一组判断规则，不根据正负标签或某个用例的答案定制提示。

## 判定与结果

只读取 `answers.has_vulnerability`，要求 `type == "noul"` 且 `noul` 为 0–1 的有限数值。`noul >= 阈值` 判为有漏洞。高分表示对“存在漏洞”回答“是”的倾向，不代表漏洞严重程度。

HTTP 错误、超时、非法 JSON、缺失分数或越界分数全部记为错误，不转成“无漏洞”，也不从严格准确率分母剔除。严格准确率为**答对数 / 本批所有选定用例**；停止后未运行的用例记为漏答。本批包含完整正负对照时，指标导出中会包含对照组正确率。

每批开始时固定配置与待测集合，顺序发送请求。**停止**只停止后续调度，已发出的请求会等待完成或超时并保留结果。重新运行会开始新一批，请先导出需要保留的结果。不会自动重试，避免重复计费。

前两个集合的样本 ID 相同，结果需要同时使用 `collection_id` 与样本 ID 关联。导出文件名含集合 ID，结果 JSONL 的每一行包含 `collection_id`，指标 JSON 记录集合及请求版本；请求 JSONL 仍是可直接发送的纯 body。离线评分时通过 `score.py --collection <集合 ID>` 选择对应答案。对比提问效果时应使用相同模型、阈值和用例范围；新增集合不会自动提高准确率，需实际复测。

本地接口：`GET /api/collections` 列出集合；`GET /api/dataset?collection_id=...` 读取一个集合（省略时为 `baseline`）；`POST /api/run` 和 `POST /api/score` 均要求顶层 `collection_id`。评分请求中每条预测也必须带相同的 `collection_id`，缺失或跨集合数据会被拒绝。

API Key 仅保存在当前页面与正在执行的请求内存中，不写磁盘、日志或结果文件；页面刷新后需重新填写。本地服务只监听回环地址，通过本地转发解决浏览器跨域访问问题。对上游重定向不自动跟随，以免把凭据发送到其他地址；遇到重定向需填写最终接口地址。

如果同一终端中 curl 可访问接口，而测试端返回 504，先重启更新后的服务并刷新页面，保持代理模式为“直连”。curl 和 Python 的代理发现规则可能不同；HTTP 504 也可能由接口自身的网关返回，不能仅凭状态码认定是代理问题。连接模式会随本批配置导出，不进入发给模型的请求 body，也不会改动系统代理或关闭 TLS 证书校验。

## 文件

- `server.py`：本地静态页面、System One 转发与评分接口。
- `static/`：单页 HTML、CSS、JavaScript，无外部 CDN。
- `test_server.py`：本地模拟上游的后端集成测试，不调用云端模型。
- `../code_vulnerability/scripts/decision_protocol.py`：前端预览、实际请求与离线导出共用的协议转换器。

测试：

```bash
python3 /Users/wh4lter/Workspace/playground/testcases/web/test_server.py
python3 /Users/wh4lter/Workspace/playground/testcases/code_vulnerability/scripts/test_decision_protocol.py
```

原始标签及评分口径见[数据集说明](../code_vulnerability/README.md)。协议依据 [TypeSafe API](https://docs.typesafe.ai/api) 和 [Noul 定义](https://docs.typesafe.ai/primitives/noul)。模拟接口测试只验证请求、结果解析和界面行为，不是实际模型准确率；用户服务还需符合该协议。
