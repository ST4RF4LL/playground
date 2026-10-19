# Decision Lab · 单页漏洞判定测试端

启动后访问 **http://127.0.0.1:8765**：

```bash
python3 /Users/wh4lter/Workspace/playground/testcases/web/server.py
```

需要 Python 3.10+，只用标准库，不需要安装前端依赖。可用 `--port 8766` 改端口。按 Ctrl+C 停止服务。

## 使用

1. 填写 **Decision-model API** 完整地址，例如 `https://api.typesafe.ai/v1/systemone` 或自建服务的 `http://127.0.0.1:8000/v1/systemone/`。程序原样发送，不额外拼接路径。
2. 填写 **模型名称**，默认 `jev-latest`。**API Key 可选**：填写后使用 `Authorization: Bearer ...`；留空不发送该请求头。TypeSafe 官方云服务需要密钥，允许匿名的兼容服务可以留空。
3. 点击案例查看实际请求 body，再单条试跑或按当前筛选批量运行。高级设置可调整阈值（默认 0.5）及连接/读取超时（默认 60 秒）。
4. 下载请求 JSONL，或导出本批结果和指标。结果 JSONL 可交给已有 `code_vulnerability/scripts/score.py` 评分。

48 条现有用例会从同级数据集自动加载。界面展示标准答案用于对照，但实际发往模型的 body 仅含 `state/model/questions`。`state` 只包含语言、判定范围、目标 CWE、上下文和代码。ID、标题、标签、解释及来源不会发送给模型。

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

真实 body 以页面预览或 `code_vulnerability/inputs/requests/<id>.json` 为准。它使用决策模型的原生问题协议，不发送通用聊天接口的 `messages` 或要求模型输出 JSON 的 prompt。

## 判定与结果

只读取 `answers.has_vulnerability`，要求 `type == "noul"` 且 `noul` 为 0–1 的有限数值。`noul >= 阈值` 判为有漏洞。高分表示对“存在漏洞”回答“是”的倾向，不代表漏洞严重程度。

HTTP 错误、超时、非法 JSON、缺失分数或越界分数全部记为错误，不转成“无漏洞”，也不从严格准确率分母剔除。严格准确率为**答对数 / 本批所有选定用例**；停止后未运行的用例记为漏答。本批包含完整正负对照时，指标导出中会包含对照组正确率。

每批开始时固定配置与待测集合，顺序发送请求。**停止**只停止后续调度，已发出的请求会等待完成或超时并保留结果。重新运行会开始新一批，请先导出需要保留的结果。不会自动重试，避免重复计费。

API Key 仅保存在当前页面与正在执行的请求内存中，不写磁盘、日志或结果文件；页面刷新后需重新填写。本地服务只监听回环地址，通过本地转发解决浏览器跨域访问问题。对上游重定向不自动跟随，以免把凭据发送到其他地址；遇到重定向需填写最终接口地址。

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
