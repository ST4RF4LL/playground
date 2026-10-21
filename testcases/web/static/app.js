"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const DEFAULTS_KEY = "decision-lab.connection-defaults";
  const PENDING_HISTORY_KEY = "decision-lab.pending-history-v1";
  const ui = {
    summary: $("dataset-summary"), form: $("config-form"), endpoint: $("endpoint"),
    model: $("model"), modelRevision: $("model-revision"), apiKey: $("api-key"), threshold: $("threshold"), timeout: $("timeout"),
    proxyMode: $("proxy-mode"), proxySummary: $("proxy-summary"),
    contextBudget: $("context-budget-note"),
    saveDefaults: $("save-defaults"), defaultsStatus: $("defaults-status"),
    collection: $("collection-selector"), collectionDescription: $("collection-description"), collectionProfile: $("collection-profile"),
    direction: $("evaluation-direction"), thresholdLabel: $("threshold-label"), questionNote: $("question-note"),
    errorTypes: $("error-types-note"), pairNote: $("pair-note"),
    run: $("run-button"), runLabel: $("run-label"), stop: $("stop-button"), single: $("run-single"),
    status: $("run-status"), statusText: $("status-text"), retry: $("retry-button"),
    search: $("search"), language: $("language-filter"), cwe: $("cwe-filter"), clear: $("clear-filters"),
    caseCount: $("case-count"), listSummary: $("list-summary"), list: $("case-list"),
    detailId: $("detail-id"), detailTitle: $("detail-title"), detailTags: $("detail-tags"),
    expected: $("expected-value"), actual: $("actual-value"), score: $("score-value"), latency: $("latency-value"),
    tabs: [...document.querySelectorAll(".preview-tab")], preview: $("preview-content"),
    previewPanel: $("preview-panel"), previewNote: $("preview-note"), copy: $("copy-preview"),
    responseIndicator: $("response-indicator"), requests: $("download-requests"),
    results: $("download-results"), metrics: $("download-metrics"),
    done: $("progress-done"), total: $("progress-total"), progress: $("progress-bar"),
    fill: $("progress-fill"), progressNote: $("progress-note"), accuracy: $("accuracy-value"),
    accuracyNote: $("accuracy-note"), fp: $("fp-value"), fn: $("fn-value"),
    errors: $("error-value"), errorNote: $("error-note"),
    collectionChecklist: $("collection-checklist"), selectCollections: $("select-all-collections"),
    clearCollections: $("clear-collections"), runCollections: $("run-collections"), batchProgress: $("batch-progress"),
    historyList: $("history-list"), historyCount: $("history-count"), historyStatus: $("history-status"),
    retryHistory: $("retry-history"), refreshHistory: $("refresh-history"), downloadHistory: $("download-history"),
  };
  const state = {
    cases: [], caseMap: new Map(), filtered: [], selectedId: null, tab: "request",
    running: false, stopRequested: false, inFlight: null, batch: null,
    results: new Map(), metrics: null, scoringError: null,
    collections: [], collection: null, requestedCollectionId: null, loading: false,
    loadVersion: 0, loadController: null, defaultsApplied: false, dirtyConfig: new Set(),
    contextLimitTokens: 262144,
    selectedCollections: new Set(), queue: null,
    history: null, pendingHistory: new Map(), historyErrors: new Map(), historyError: null,
    historyStorageError: null, historyBusy: false, historyVersion: 0,
  };
  const languageNames = { java: "Java", python: "Python", c: "C", javascript: "JavaScript", cpp: "C++", go: "Go" };
  const cweNames = {
    "CWE-22": "路径遍历", "CWE-78": "命令注入", "CWE-79": "跨站脚本",
    "CWE-89": "SQL 注入", "CWE-90": "LDAP 注入", "CWE-129": "数组索引",
    "CWE-327": "弱加密", "CWE-328": "弱哈希", "CWE-330": "不安全随机数",
    "CWE-501": "信任边界", "CWE-502": "不安全反序列化", "CWE-611": "XML 外部实体",
    "CWE-639": "对象授权", "CWE-643": "XPath 注入", "CWE-787": "越界写入",
    "CWE-918": "服务端请求伪造（SSRF）",
  };

  function setStatus(message, kind = "") {
    ui.status.className = `run-status${kind ? ` ${kind}` : ""}`;
    ui.statusText.textContent = message;
  }

  function expectedVerdict(item) {
    return typeof item.expected === "object" && item.expected !== null ? item.expected.verdict : item.expected;
  }

  function verdictLabel(verdict) {
    const meta = state.collection;
    return verdict === positiveLabel() ? (meta?.positive_label_text || "有漏洞")
      : verdict === negativeLabel() ? (meta?.negative_label_text || "无目标漏洞") : "无有效判断";
  }

  function positiveLabel() { return state.collection?.positive_label || "vulnerable"; }
  function negativeLabel() { return state.collection?.negative_label || "not_vulnerable"; }
  function isAgentTask() { return state.collection?.task_type === "agent_safety"; }
  function categoryLabel() { return state.collection?.category_label || "漏洞类别"; }

  function safeText(value) {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  // The key never enters browser storage or an exported object. Also redact any
  // accidental upstream echo before keeping a response in the result collection.
  function redactSecrets(value, key = state.batch?.config.api_key || ui.apiKey.value.trim()) {
    if (typeof value === "string") return key ? value.split(key).join("[REDACTED]") : value;
    if (Array.isArray(value)) return value.map((item) => redactSecrets(item, key));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([name, item]) => [
        name, /^(api[-_]?key|authorization|proxy-authorization)$/i.test(name) ? "[REDACTED]" : redactSecrets(item, key),
      ]));
    }
    return value;
  }

  function currentModel() {
    return state.running ? (state.batch?.config.model || state.queue?.config.model || ui.model.value.trim()) : ui.model.value.trim() || "jev-latest";
  }

  function requestBody(item, model = currentModel()) {
    // Only replace model. IDs, titles, gold labels, and rationale never enter the body.
    return { ...item.body, model };
  }

  function resultState(item) {
    if (state.inFlight === item.id) return { label: "运行中", kind: "running" };
    const result = state.results.get(item.id);
    if (!result) return { label: "待运行", kind: "" };
    if (result.status === "error") return { label: "错误", kind: "error" };
    if (result.verdict === expectedVerdict(item)) return { label: "一致", kind: "correct" };
    return { label: result.verdict === positiveLabel() ? "误报 FP" : "漏报 FN", kind: "incorrect" };
  }

  function makeTag(label) {
    const span = document.createElement("span");
    span.className = "tag";
    span.textContent = label;
    return span;
  }

  function renderList() {
    const scrollTop = ui.list.scrollTop;
    const fragment = document.createDocumentFragment();
    if (!state.filtered.length) {
      const empty = document.createElement("p");
      empty.className = "empty-list";
      empty.textContent = state.loading ? "正在加载测试集合…" : state.cases.length ? "没有匹配的用例，请调整筛选条件。" : "暂无可用的测试用例。";
      fragment.append(empty);
    }
    for (const item of state.filtered) {
      const wrapper = document.createElement("div");
      wrapper.setAttribute("role", "listitem");
      const row = document.createElement("button");
      row.type = "button";
      row.className = `case-row${item.id === state.selectedId ? " active" : ""}`;
      row.setAttribute("aria-pressed", String(item.id === state.selectedId));
      row.title = `${item.title} · ${item.id}`;
      const index = document.createElement("span");
      index.className = "case-index";
      index.textContent = String(item._index + 1).padStart(2, "0");
      const main = document.createElement("span");
      main.className = "case-main";
      const title = document.createElement("span");
      title.className = "case-title";
      title.textContent = item.title;
      const meta = document.createElement("span");
      meta.className = "case-meta";
      meta.append(makeTag(item.language === "agent_trace" ? "Agent 轨迹" : languageNames[item.language] || item.language), makeTag(item.focus_cwe));
      const expected = document.createElement("span");
      expected.className = `expected-mini${expectedVerdict(item) === positiveLabel() ? " positive" : ""}`;
      expected.textContent = verdictLabel(expectedVerdict(item));
      meta.append(expected);
      main.append(title, meta);
      const status = resultState(item);
      const badge = document.createElement("span");
      badge.className = `case-state ${status.kind}`;
      badge.textContent = status.label;
      row.append(index, main, badge);
      row.addEventListener("click", () => {
        state.selectedId = item.id;
        renderList();
        renderDetail();
        renderControls();
      });
      wrapper.append(row);
      fragment.append(wrapper);
    }
    ui.list.replaceChildren(fragment);
    ui.list.scrollTop = scrollTop;
    ui.caseCount.textContent = state.filtered.length;
    ui.listSummary.textContent = `${state.filtered.length} / ${state.cases.length} 条用例`;
  }

  function renderDetail() {
    const item = state.caseMap.get(state.selectedId);
    const result = item ? state.results.get(item.id) : null;
    const budget = item?.context_budget;
    const limit = budget?.limit_tokens ?? state.contextLimitTokens;
    ui.contextBudget.textContent = `上下文预算 256K（${limit.toLocaleString("zh-CN")} token）。` + (budget
      ? `当前选中请求的保守估算上界：${budget.estimated_tokens_upper_bound.toLocaleString("zh-CN")}（UTF-8 字节 + ${budget.schema_allowance_tokens.toLocaleString("zh-CN")} 余量，非精确 token 数）。${budget.within_budget ? "在预算内。" : "超出预算，发送时将拒绝。"}输入不会截断。`
      : "选择用例后显示保守估算；超出预算将拒绝发送，不截断输入。");
    ui.detailId.textContent = item?.id || "CASE PREVIEW";
    ui.detailTitle.textContent = item?.title || "暂无选中的用例";
    ui.detailTags.replaceChildren();
    if (item) {
      ui.detailTags.append(makeTag(item.language === "agent_trace" ? "Agent 轨迹" : languageNames[item.language] || item.language), makeTag(item.focus_cwe));
      ui.detailTags.append(makeTag(item.suite === "owasp_target_cwe" ? "OWASP 基准" : item.suite === "curated_contrast" ? "成对对照" : item.suite));
    }
    ui.expected.textContent = item ? verdictLabel(expectedVerdict(item)) : "—";
    ui.actual.textContent = state.inFlight === item?.id ? "运行中…" : result ? result.status === "error" ? "请求 / 解析错误" : verdictLabel(result.verdict) : "未运行";
    ui.actual.className = result && item ? resultState(item).kind : "";
    ui.score.textContent = result?.status === "ok" && Number.isFinite(result.score) ? result.score.toFixed(4) : "—";
    ui.latency.textContent = Number.isFinite(result?.latency_ms) ? `${(result.latency_ms / 1000).toFixed(2)} s` : "—";
    ui.responseIndicator.hidden = !result;
    ui.previewPanel.className = `preview-panel ${state.tab}${!item || (state.tab === "response" && !result) ? " empty" : ""}`;
    ui.previewPanel.setAttribute("aria-labelledby", `tab-${state.tab}`);
    for (const tab of ui.tabs) {
      const active = tab.dataset.tab === state.tab;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    if (!item) {
      ui.preview.textContent = "在左侧选择一个用例，查看可直接发送的请求。";
      ui.previewNote.textContent = "请求仅包含评估内容，不包含标准答案。";
    } else if (state.tab === "request") {
      ui.preview.textContent = JSON.stringify(requestBody(item), null, 2);
      ui.previewNote.textContent = `直接发送的 System One 请求 · model: ${currentModel()} · 不包含标准答案`;
    } else if (state.tab === "code") {
      ui.preview.textContent = item.code;
      ui.previewNote.textContent = isAgentTask()
        ? "完整工具定义与交互轨迹；评估整段 Agent 行为。标准答案和风险说明不会发送给模型。"
        : "源码来自当前用例；环境约定与漏洞范围可在请求 Body 的 state 中查看。";
    } else if (result) {
      const details = [];
      if (result.http_status) details.push(`HTTP ${result.http_status}`);
      if (result.response_model) details.push(`模型 ${result.response_model}`);
      if (result.error) details.push(safeText(result.error));
      ui.previewNote.textContent = details.length ? details.join(" · ") : "模型原始响应";
      ui.preview.textContent = result.raw_response === undefined || result.raw_response === null ? result.error ? safeText(result.error) : "响应为空。" : safeText(result.raw_response);
    } else {
      ui.previewNote.textContent = "运行后可查看原始响应、分值与耗时。";
      ui.preview.textContent = state.inFlight === item.id ? "请求已发出，正在等待模型响应…" : "这个用例还没有运行。\n\n点击「单条试跑」，或运行当前筛选的所有用例。";
    }
    ui.copy.disabled = !item || (state.tab === "response" && !result);
  }

  function localCounts() {
    const ids = state.batch?.ids || [];
    const counts = { tp: 0, tn: 0, fp: 0, fn: 0, errors: 0, missing: 0 };
    for (const id of ids) {
      const result = state.results.get(id);
      if (!result) counts.missing += 1;
      else if (result.status !== "ok") counts.errors += 1;
      else {
        const expected = expectedVerdict(state.caseMap.get(id));
        const name = result.verdict === positiveLabel() ? expected === positiveLabel() ? "tp" : "fp" : expected === negativeLabel() ? "tn" : "fn";
        counts[name] += 1;
      }
    }
    return counts;
  }

  function renderMetrics() {
    const total = state.batch?.ids.length ?? state.filtered.length;
    const completed = state.results.size;
    const counts = localCounts();
    const correct = counts.tp + counts.tn;
    const percentage = total ? Math.round(completed / total * 100) : 0;
    ui.done.textContent = completed;
    ui.total.textContent = total;
    ui.fill.style.width = `${percentage}%`;
    ui.progress.setAttribute("aria-valuenow", String(percentage));
    ui.progressNote.textContent = !state.batch ? "运行后按本批全部用例统计" : state.running ? `${counts.missing} 条待完成 · 本批范围已锁定` : counts.missing ? `${counts.missing} 条未执行 · 仍计入分母` : "本批全部请求已完成";
    ui.accuracy.textContent = state.batch && total ? `${(correct / total * 100).toFixed(1)}%` : "—";
    ui.accuracyNote.textContent = state.batch ? `${correct} 条正确 / ${total} 条本批用例` : "正确数 / 本批全部用例";
    ui.fp.textContent = counts.fp;
    ui.fn.textContent = counts.fn;
    ui.errors.textContent = counts.errors;
    ui.errors.classList.toggle("error", counts.errors > 0);
    ui.errorNote.textContent = counts.errors ? `${counts.errors} 条错误 · ${counts.missing} 条未答` : "错误与未答均计入准确率分母";
    const pairs = state.metrics?.contrast_pairs;
    ui.pairNote.textContent = pairs?.total
      ? `完整配对均判对：${pairs.both_correct} / ${pairs.total}（${(pairs.both_correct_rate * 100).toFixed(1)}%）`
      : isAgentTask() ? "按完整轨迹独立评分" : "配对指标在运行包含完整正负对的批次后显示";
  }

  function renderControls() {
    ui.saveDefaults.disabled = state.running;
    for (const input of ui.form.querySelectorAll("input, select")) input.disabled = state.running;
    ui.proxySummary.textContent = ui.proxyMode.value === "system" ? "使用环境 / 系统代理" : "默认直连（不使用代理）";
    ui.collection.disabled = state.running || !state.collections.length;
    if (state.requestedCollectionId) ui.collection.value = state.requestedCollectionId;
    if (state.collection) {
      ui.collectionDescription.textContent = state.collection.description || state.collection.name;
      ui.collectionProfile.textContent = `${state.collection.count ?? state.cases.length} 条用例 · 切换浏览集合会清空临时详情，运行汇总独立保存。`;
      ui.direction.textContent = `评估方向：${state.collection.evaluation_direction}`;
    } else {
      const pending = state.collections.find((item) => item.id === state.requestedCollectionId);
      ui.collectionDescription.textContent = state.loading ? `正在加载${pending ? `「${pending.name}」` : "测试集合"}，完成后即可运行。` : "集合加载失败，当前没有可运行的数据。请重试或切换集合。";
      ui.collectionProfile.textContent = "连接配置保持不变；只有成功加载后才能运行与导出。";
      ui.direction.textContent = "评估方向：等待集合加载";
    }
    $("tab-code").textContent = state.collection?.input_label || "源代码";
    ui.search.placeholder = isAgentTask() ? "搜索标题、ID 或交互轨迹…" : "搜索标题、ID 或代码…";
    ui.language.closest("label").hidden = isAgentTask();
    ui.cwe.setAttribute("aria-label", `按${categoryLabel()}筛选`);
    ui.thresholdLabel.textContent = `${verdictLabel(positiveLabel())}判定阈值`;
    ui.questionNote.textContent = `分值 ≥ 阈值时判为“${verdictLabel(positiveLabel())}”。请求按顺序执行。`;
    ui.errorTypes.textContent = isAgentTask() ? "FP：安全行为误报 · FN：不安全行为漏报" : "FP：无目标漏洞误报 · FN：目标漏洞漏报";
    for (const filter of [ui.search, ui.language, ui.cwe]) filter.disabled = state.loading || !state.cases.length;
    ui.run.disabled = state.running || state.loading || !state.collection || !state.filtered.length;
    ui.runLabel.textContent = state.loading ? "正在加载集合…" : state.running ? `运行中 ${state.results.size} / ${state.batch?.ids.length || 0}` : `运行当前用例 (${state.filtered.length})`;
    ui.run.title = "开始新批次，清空上批结果";
    ui.single.disabled = state.running || state.loading || !state.collection || !state.selectedId;
    ui.single.title = "以此用例开始新批次，清空上批结果";
    ui.stop.disabled = !state.running || state.stopRequested;
    ui.stop.textContent = state.stopRequested && state.running ? "等待当前请求…" : "■ 停止";
    ui.requests.disabled = state.loading || !state.collection || !state.filtered.length;
    ui.results.disabled = state.running || state.loading || !state.results.size;
    ui.metrics.disabled = state.running || state.loading || !state.metrics;
    ui.clear.hidden = !(ui.search.value || ui.language.value || ui.cwe.value);
    renderCollectionControls();
  }

  function render() {
    renderList();
    renderDetail();
    renderMetrics();
    renderControls();
  }

  function renderCollectionChoices() {
    const fragment = document.createDocumentFragment();
    for (const item of state.collections) {
      const label = document.createElement("label");
      label.className = "collection-choice";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = item.id;
      checkbox.checked = state.selectedCollections.has(item.id);
      const text = document.createElement("span");
      const name = document.createElement("strong");
      name.textContent = `${item.name} · ${item.count} 条`;
      const direction = document.createElement("small");
      direction.textContent = item.evaluation_direction || item.description || "独立评估";
      text.append(name, direction);
      label.append(checkbox, text);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) state.selectedCollections.add(item.id);
        else state.selectedCollections.delete(item.id);
        renderCollectionControls();
      });
      fragment.append(label);
    }
    ui.collectionChecklist.replaceChildren(fragment);
    renderCollectionControls();
  }

  function renderCollectionControls() {
    const selected = state.collections.filter((item) => state.selectedCollections.has(item.id));
    const count = selected.reduce((sum, item) => sum + item.count, 0);
    for (const checkbox of ui.collectionChecklist.querySelectorAll("input")) {
      checkbox.disabled = state.running;
      checkbox.checked = state.selectedCollections.has(checkbox.value);
    }
    ui.selectCollections.disabled = state.running || !state.collections.length;
    ui.clearCollections.disabled = state.running || !selected.length;
    ui.runCollections.disabled = state.running || state.loading || !selected.length;
    ui.runCollections.textContent = `运行所选集合${selected.length ? ` (${selected.length})` : ""}`;
    const queue = state.queue;
    if (queue && state.running) {
      const name = state.collections.find((item) => item.id === queue.targets[queue.index]?.collection_id)?.name || "集合";
      ui.batchProgress.textContent = `${state.stopRequested ? "正在停止" : "正在执行"} · 集合 ${queue.index + 1} / ${queue.targets.length}：${name} · 已执行 ${queue.completed + state.results.size} / ${queue.total} 条。下方指标仅对应当前集合。`;
    } else if (queue?.finished) {
      ui.batchProgress.textContent = `${queue.stopped ? "批量已停止" : queue.failed ? "批量已中断" : "批量已完成"} · ${queue.finishedCollections} / ${queue.targets.length} 个集合有运行记录，已执行 ${queue.completed} / ${queue.total} 条。已选 ${selected.length} 个集合，可再次运行。`;
    } else {
      ui.batchProgress.textContent = selected.length ? `已选 ${selected.length} 个集合，共 ${count} 条；每个集合独立保存汇总。` : "选择一个或多个测试集合。";
    }
  }

  function historyRows() {
    const rows = [];
    for (const [model, collections] of Object.entries(state.history?.models || {})) {
      for (const [collection_id, records] of Object.entries(collections)) {
        for (const record of records) rows.push({ ...record, model, collection_id });
      }
    }
    return rows.sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)));
  }

  function renderHistory() {
    const rows = historyRows();
    ui.historyCount.textContent = rows.length;
    const pending = [...state.pendingHistory.values()].filter((entry) => !entry.incomplete);
    ui.retryHistory.hidden = !pending.length;
    ui.retryHistory.disabled = state.historyBusy;
    ui.retryHistory.textContent = `重试保存 (${pending.length})`;
    ui.refreshHistory.disabled = state.historyBusy;
    ui.downloadHistory.disabled = !state.history || state.historyBusy;
    const messages = [];
    if (state.historyError) messages.push(`历史读取失败：${state.historyError}`);
    if (pending.length) messages.push(`${pending.length} 次运行尚未保存，切换集合后仍可重试。${[...state.historyErrors.values()][0] || ""}`);
    if (state.historyStorageError) messages.push(state.historyStorageError);
    ui.historyStatus.textContent = messages.join(" ") || (state.historyBusy ? "正在同步运行汇总…" : rows.length ? `已保存 ${rows.length} 次运行。${rows.length > 50 ? "列表显示最近 50 次，JSON 包含全部历史。" : ""}` : "尚无运行记录。单条、筛选运行和多集合批量运行都会自动保存汇总。");
    ui.historyStatus.classList.toggle("error", messages.length > 0);
    const fragment = document.createDocumentFragment();
    for (const record of rows.slice(0, 50)) {
      const row = document.createElement("tr");
      const counts = record.counts || {};
      const metrics = record.metrics || {};
      const date = new Date(record.started_at);
      const collection = state.collections.find((item) => item.id === record.collection_id);
      const cells = [
        [Number.isNaN(date.valueOf()) ? record.started_at : date.toLocaleString("zh-CN"), { completed: "已完成", stopped: "已停止", interrupted: "已中断" }[record.status] || record.status],
        [record.model, collection?.name || record.collection_id],
        [`${record.scope === "full" ? "全集" : "部分用例"} · ${record.selected_count ?? counts.total} 条`, `已执行 ${(counts.total || 0) - (counts.missing || 0)} · 阈值 ${record.threshold}`],
        [Number.isFinite(metrics.accuracy) ? `${(metrics.accuracy * 100).toFixed(1)}%` : "—", `${counts.correct ?? 0} 条正确`],
        [`${counts.tp ?? 0} / ${counts.tn ?? 0}`],
        [`${counts.fp ?? 0} / ${counts.fn ?? 0}`],
        [`${counts.error ?? 0} / ${counts.missing ?? 0}`],
      ];
      row.title = `运行 ${record.run_id} · 集合版本 ${(record.collection_fingerprint || "").slice(0, 12)}${record.model_revision ? ` · ${record.model_revision}` : ""}`;
      for (const [main, secondary] of cells) {
        const cell = document.createElement("td");
        const primary = document.createElement("span");
        primary.textContent = main;
        cell.append(primary);
        if (secondary) {
          const small = document.createElement("small");
          small.textContent = secondary;
          cell.append(small);
        }
        row.append(cell);
      }
      fragment.append(row);
    }
    ui.historyList.replaceChildren(fragment);
  }

  function persistPendingHistory() {
    try {
      // Keep checkpoints local to this tab: opening another model comparison tab
      // must not finalize a run that is still active here.
      if (state.pendingHistory.size) sessionStorage.setItem(PENDING_HISTORY_KEY, JSON.stringify([...state.pendingHistory.values()]));
      else sessionStorage.removeItem(PENDING_HISTORY_KEY);
      state.historyStorageError = null;
    } catch {
      state.historyStorageError = "浏览器无法缓存待保存汇总；请保持页面打开并重试保存。";
    }
  }

  function restorePendingHistory() {
    try {
      const pending = JSON.parse(sessionStorage.getItem(PENDING_HISTORY_KEY) || "[]");
      if (!Array.isArray(pending)) throw new Error("invalid pending history");
      for (const entry of pending) {
        if (!entry?.payload?.run_id || !Array.isArray(entry.payload.case_ids) || !Array.isArray(entry.payload.predictions)) continue;
        if (entry.incomplete) {
          entry.payload.status = "interrupted";
          entry.payload.finished_at = new Date().toISOString();
          entry.incomplete = false;
        }
        state.pendingHistory.set(entry.payload.run_id, entry);
      }
      persistPendingHistory();
    } catch {
      state.historyStorageError = "未能读取浏览器中待保存的汇总，请保留浏览器数据以便排查。";
    }
  }

  async function loadHistory() {
    const version = ++state.historyVersion;
    try {
      const response = await fetch("/api/history", { cache: "no-store", credentials: "same-origin" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.schema_version !== 1 || !data.models || typeof data.models !== "object" || Array.isArray(data.models)) throw new Error("历史格式无效");
      if (version !== state.historyVersion) return false;
      state.history = data;
      state.historyError = null;
      renderHistory();
      return true;
    } catch (error) {
      if (version === state.historyVersion) state.historyError = redactSecrets(error.message);
    }
    renderHistory();
    return false;
  }

  function checkpointBatch(incomplete = true) {
    const batch = state.batch;
    const payload = {
      run_id: batch.run_id, batch_id: batch.batch_id, collection_id: batch.collection_id,
      collection_fingerprint: batch.collection.fingerprint,
      case_ids: [...batch.ids],
      predictions: [...state.results.values()].map((result) => result.status === "ok"
        ? { id: result.id, collection_id: batch.collection_id, status: "ok", score: result.score }
        : { id: result.id, collection_id: batch.collection_id, status: "error" }),
      config: { ...batch.history_config }, started_at: batch.started_at,
      finished_at: batch.finished_at || new Date().toISOString(), status: batch.status || "interrupted",
    };
    state.pendingHistory.set(batch.run_id, { payload, incomplete });
    persistPendingHistory();
    renderHistory();
  }

  async function saveHistoryEntry(entry) {
    try {
      const data = await post("/api/history", entry.payload);
      if (data.record?.run_id !== entry.payload.run_id) throw new Error("保存服务返回了不匹配的运行记录。");
      state.pendingHistory.delete(entry.payload.run_id);
      state.historyErrors.delete(entry.payload.run_id);
      persistPendingHistory();
      // Append the confirmed server summary. Pending inputs never enter exports.
      state.historyVersion += 1;
      if (!state.history) state.history = { schema_version: 1, models: {} };
      const models = state.history.models;
      const model = entry.payload.config.model;
      const collection = entry.payload.collection_id;
      if (!Object.hasOwn(models, model)) Object.defineProperty(models, model, { value: {}, enumerable: true, configurable: true, writable: true });
      if (!Object.hasOwn(models[model], collection)) Object.defineProperty(models[model], collection, { value: [], enumerable: true, configurable: true, writable: true });
      const records = models[model][collection];
      if (!records.some((record) => record.run_id === data.record.run_id)) records.push(data.record);
      return true;
    } catch (error) {
      state.historyErrors.set(entry.payload.run_id, redactSecrets(error.message));
      return false;
    } finally {
      renderHistory();
    }
  }

  async function retryPendingHistory() {
    if (state.historyBusy) return;
    state.historyBusy = true;
    renderHistory();
    try {
      for (const entry of [...state.pendingHistory.values()]) {
        if (!entry.incomplete) await saveHistoryEntry(entry);
      }
      await loadHistory();
    } finally {
      state.historyBusy = false;
      renderHistory();
    }
  }

  function applyFilters() {
    const query = ui.search.value.trim().toLowerCase();
    state.filtered = state.cases.filter((item) =>
      (!ui.language.value || item.language === ui.language.value) &&
      (!ui.cwe.value || item.focus_cwe === ui.cwe.value) &&
      (!query || `${item.id} ${item.title} ${item.language} ${item.focus_cwe} ${item.code}`.toLowerCase().includes(query))
    );
    if (!state.filtered.some((item) => item.id === state.selectedId)) state.selectedId = state.filtered[0]?.id || null;
    render();
  }

  function readConnection() {
    if (!ui.endpoint.reportValidity() || !ui.model.reportValidity()) return null;
    const endpoint = ui.endpoint.value.trim();
    const model = ui.model.value.trim();
    let url;
    try { url = new URL(endpoint); } catch { setStatus("请填写完整的 API URL。", "error"); ui.endpoint.focus(); return null; }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
      setStatus("API URL 需要以 http:// 或 https:// 开头，鉴权信息请填入 API key。", "error");
      ui.endpoint.focus();
      return null;
    }
    if (!model) { setStatus("请填写模型名称。", "error"); ui.model.focus(); return null; }
    return { endpoint, model };
  }

  function readConfig() {
    if (!ui.form.reportValidity()) return null;
    const connection = readConnection();
    if (!connection) return null;
    const { endpoint, model } = connection;
    const threshold = Number(ui.threshold.value);
    const timeout = Number(ui.timeout.value);
    const proxy_mode = ui.proxyMode.value;
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1 || !Number.isInteger(timeout) || timeout < 1 || timeout > 300) {
      setStatus("判定阈值应在 0–1 之间，超时应为 1–300 秒的整数。", "error");
      return null;
    }
    if (!["direct", "system"].includes(proxy_mode)) {
      setStatus("请选择有效的代理模式。", "error");
      ui.proxyMode.focus();
      return null;
    }
    return Object.freeze({ endpoint, api_key: ui.apiKey.value.trim(), model, threshold, timeout, proxy_mode, model_revision: ui.modelRevision.value.trim() });
  }

  function restoreDefaults() {
    try {
      const saved = JSON.parse(localStorage.getItem(DEFAULTS_KEY));
      if (typeof saved?.endpoint !== "string" || !saved.endpoint.trim() || typeof saved?.model !== "string" || !saved.model.trim()) return;
      ui.endpoint.value = saved.endpoint.trim();
      ui.model.value = saved.model.trim();
      // Saved connection values take priority over the initial server defaults.
      state.dirtyConfig.add(ui.endpoint.id).add(ui.model.id);
      ui.defaultsStatus.textContent = "已载入当前浏览器保存的 API 地址和模型名称。";
    } catch {
      ui.defaultsStatus.textContent = "无法读取浏览器默认设置，可重新填写并保存。";
    }
  }

  async function post(path, payload) {
    const response = await fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json", "X-Testbench-Request": "1" },
      body: JSON.stringify(payload), credentials: "same-origin", cache: "no-store",
    });
    let data;
    try { data = await response.json(); } catch { throw new Error(`本地服务返回了无法解析的响应（HTTP ${response.status}）。`); }
    if (!response.ok) throw new Error(data.error ? safeText(data.error) : `本地服务请求失败（HTTP ${response.status}）。`);
    return data;
  }

  async function refreshScore() {
    try {
      const collection_id = state.batch.collection_id;
      const predictions = [...state.results.values()].map((result) => result.status === "ok" ? { id: result.id, collection_id, verdict: result.verdict } : { id: result.id, collection_id, error: true });
      const metrics = await post("/api/score", { collection_id, case_ids: state.batch.ids, predictions });
      if (metrics.collection_id !== collection_id) throw new Error("指标服务返回了不匹配的测试集合。");
      state.metrics = metrics;
      state.scoringError = null;
    } catch (error) {
      state.metrics = null;
      state.scoringError = redactSecrets(error.message);
    }
  }

  async function startBatch(ids) {
    if (state.running || state.loading || !state.collection || !ids.length) return;
    await startQueue([{ collection_id: state.collection.id, ids: [...ids] }]);
  }

  async function startQueue(targets) {
    if (state.running || state.loading || !targets.length) return;
    const config = readConfig();
    if (!config) return;
    state.running = true;
    state.stopRequested = false;
    const queue = {
      targets, config, batch_id: crypto.randomUUID(), index: 0, completed: 0, finishedCollections: 0, errors: 0,
      total: targets.reduce((sum, target) => sum + (target.ids?.length ?? state.collections.find((item) => item.id === target.collection_id)?.count ?? 0), 0),
      finished: false, stopped: false, failed: false,
    };
    state.queue = queue;
    renderControls();
    try {
      const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.endpoint));
      const historyConfig = Object.freeze({
        endpoint_fingerprint: [...new Uint8Array(hash)].map((value) => value.toString(16).padStart(2, "0")).join(""),
        model: config.model, model_revision: config.model_revision, threshold: config.threshold,
        timeout: config.timeout, proxy_mode: config.proxy_mode,
      });
      for (let index = 0; index < targets.length; index += 1) {
        if (state.stopRequested) break;
        queue.index = index;
        const target = targets[index];
        // Multi-collection runs always reload the full collection; browsing filters
        // never determine a queued collection's denominator.
        if (!target.ids || state.collection?.id !== target.collection_id) {
          const loaded = await loadDataset(target.collection_id, true);
          if (!loaded) throw new Error("测试集合未能加载，已停止后续集合。已保存的汇总仍保留。");
        }
        if (state.stopRequested) break;
        await runCollection(target.ids || state.cases.map((item) => item.id), config, historyConfig, queue.batch_id);
        queue.completed += state.results.size;
        queue.errors += localCounts().errors;
        queue.finishedCollections += 1;
      }
    } catch (error) {
      queue.failed = true;
      queue.error = redactSecrets(error.message, config.api_key);
    } finally {
      state.running = false;
      state.inFlight = null;
      queue.finished = true;
      queue.stopped = state.stopRequested;
      queue.config = { model: config.model };
      let message = queue.failed ? queue.error : `${queue.stopped ? "已停止" : "运行完成"} · ${queue.finishedCollections} / ${queue.targets.length} 个集合，已执行 ${queue.completed} / ${queue.total} 条，${queue.errors} 条请求或解析错误。`;
      const unsaved = [...state.pendingHistory.values()].filter((entry) => !entry.incomplete).length;
      if (unsaved) message += ` ${unsaved} 次汇总尚未保存，请在下方历史区重试。`;
      else if (queue.finishedCollections) message += " 汇总已自动保存。";
      if (state.scoringError) message += ` 当前集合详细指标暂不可用：${state.scoringError}`;
      setStatus(message, queue.failed || queue.errors || unsaved ? "error" : "success");
      render();
      renderHistory();
    }
  }

  async function runCollection(ids, config, historyConfig, batchId) {
    state.batch = {
      run_id: crypto.randomUUID(), batch_id: batchId, ids: Object.freeze([...ids]),
      collection_id: state.collection.id, collection: Object.freeze({ ...state.collection }),
      config, history_config: historyConfig, context_limit_tokens: state.contextLimitTokens,
      started_at: new Date().toISOString(), finished_at: null,
    };
    state.results.clear();
    state.metrics = null;
    state.scoringError = null;
    checkpointBatch();
    render();
    try {
      for (const id of state.batch.ids) {
        if (state.stopRequested) break;
        state.inFlight = id;
        const item = state.caseMap.get(id);
        setStatus(`正在运行 ${state.results.size + 1} / ${state.batch.ids.length} · ${item.title}`, "running");
        render();
        const started = performance.now();
        let result;
        try {
          result = await post("/api/run", { collection_id: state.batch.collection_id, case_id: id, config });
          if (result.id !== id || result.collection_id !== state.batch.collection_id || !["ok", "error"].includes(result.status)) throw new Error("本地服务返回了不匹配的集合或用例结果。");
          if (result.status === "ok" && (![positiveLabel(), negativeLabel()].includes(result.verdict) || !Number.isFinite(result.score) || result.score < 0 || result.score > 1)) throw new Error("模型响应没有有效的判断或 noul 分值。");
        } catch (error) {
          result = { id, collection_id: state.batch.collection_id, status: "error", latency_ms: Math.round(performance.now() - started), error: error.message, raw_response: null };
        }
        state.results.set(id, redactSecrets(result, config.api_key));
        state.inFlight = null;
        checkpointBatch();
        render();
      }
    } finally {
      state.inFlight = null;
      state.batch.finished_at = new Date().toISOString();
      state.batch.status = state.results.size === state.batch.ids.length ? "completed" : state.stopRequested ? "stopped" : "interrupted";
      checkpointBatch(false);
      setStatus(`正在保存「${state.collection.name}」的运行汇总…`, "running");
      await saveHistoryEntry(state.pendingHistory.get(state.batch.run_id));
      await refreshScore();
      // Keep only non-secret batch metadata after the requests have finished.
      state.batch.config = Object.freeze({ endpoint: config.endpoint, model: config.model, threshold: config.threshold, timeout: config.timeout, proxy_mode: config.proxy_mode, model_revision: config.model_revision });
      render();
    }
  }

  function download(name, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportableResult(result) {
    const row = {};
    for (const key of ["id", "collection_id", "status", "verdict", "score", "latency_ms", "http_status", "response_model", "context_budget", "error", "raw_response"]) {
      if (result[key] !== undefined) row[key] = result[key];
    }
    return redactSecrets(row);
  }

  function applyInitialDefaults(defaults) {
    if (state.defaultsApplied) return;
    const entries = [[ui.endpoint, defaults.endpoint], [ui.model, defaults.model],
      [ui.threshold, defaults.threshold], [ui.timeout, defaults.timeout],
      [ui.proxyMode, ["direct", "system"].includes(defaults.proxy_mode) ? defaults.proxy_mode : undefined]];
    for (const [input, value] of entries) {
      if (value !== undefined && value !== null && !state.dirtyConfig.has(input.id)) input.value = value;
    }
    state.defaultsApplied = true;
  }

  async function loadDataset(collectionId = state.requestedCollectionId, fromQueue = false) {
    if (state.running && !fromQueue) return false;
    const version = ++state.loadVersion;
    state.loadController?.abort();
    const controller = new AbortController();
    state.loadController = controller;
    state.requestedCollectionId = collectionId || null;
    state.loading = true;
    // Clear the previous collection immediately: identical case IDs must never
    // leave old bodies, predictions, or denominators attached to a new selection.
    state.collection = null;
    state.cases = [];
    state.caseMap = new Map();
    state.filtered = [];
    state.selectedId = null;
    state.batch = null;
    state.inFlight = null;
    if (!fromQueue) state.stopRequested = false;
    state.results.clear();
    state.metrics = null;
    state.scoringError = null;
    ui.search.value = "";
    ui.language.replaceChildren(new Option("全部语言", ""));
    ui.cwe.replaceChildren(new Option("全部类别", ""));
    ui.retry.hidden = true;
    ui.summary.textContent = "正在加载测试集合…";
    setStatus("正在读取测试集合…");
    render();
    try {
      const path = `/api/dataset${collectionId ? `?collection_id=${encodeURIComponent(collectionId)}` : ""}`;
      const response = await fetch(path, { cache: "no-store", credentials: "same-origin", signal: controller.signal });
      if (!response.ok) throw new Error(`集合加载失败（HTTP ${response.status}）。`);
      const data = await response.json();
      if (version !== state.loadVersion) return;
      if (!Array.isArray(data.cases) || !data.cases.length) throw new Error("测试集合为空或格式无效。");
      if (!data.collection?.id || !Array.isArray(data.collections) || !data.collections.some((item) => item.id === data.collection.id)) throw new Error("测试集合元数据缺失或格式无效。");
      if (collectionId && data.collection.id !== collectionId) throw new Error("服务返回了不匹配的测试集合，请重试。");
      const cases = data.cases.map((item, index) => ({ ...item, _index: index }));
      const caseMap = new Map(cases.map((item) => [item.id, item]));
      if (caseMap.size !== cases.length) throw new Error("测试集合包含重复的用例 ID。");
      state.collection = Object.freeze({ ...data.collection });
      state.collections = data.collections;
      renderCollectionChoices();
      renderHistory();
      state.requestedCollectionId = data.collection.id;
      state.cases = cases;
      state.caseMap = caseMap;
      ui.collection.replaceChildren(...state.collections.map((item) => new Option(
        `${item.name} · ${item.count} 条`, item.id)));
      ui.collection.value = state.collection.id;
      if (Number.isSafeInteger(data.defaults?.context_limit_tokens) && data.defaults.context_limit_tokens > 0) state.contextLimitTokens = data.defaults.context_limit_tokens;
      applyInitialDefaults(data.defaults || {});
      const languages = [...new Set(state.cases.map((item) => item.language))];
      const categories = [...new Set(state.cases.map((item) => item.focus_cwe))].sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
      ui.language.replaceChildren(new Option("全部语言", ""), ...languages.map((language) => new Option(languageNames[language] || language, language)));
      ui.cwe.replaceChildren(new Option(`全部${categoryLabel()}`, ""), ...categories.map((cwe) => new Option(`${cwe}${cweNames[cwe] ? ` · ${cweNames[cwe]}` : ""}`, cwe)));
      const positive = state.cases.filter((item) => expectedVerdict(item) === positiveLabel()).length;
      ui.summary.textContent = `${state.collection.name} · ${state.cases.length} 条用例 · ${isAgentTask() ? "完整交互轨迹" : `${languages.length} 种语言 · ${categories.length} 类漏洞`} · ${verdictLabel(positiveLabel())} ${positive} / ${verdictLabel(negativeLabel())} ${state.cases.length - positive}`;
      state.loading = false;
      state.loadController = null;
      applyFilters();
      setStatus(`「${state.collection.name}」已就绪。每次运行自动保存汇总，切换浏览集合只清空临时详情。`, "success");
      return true;
    } catch (error) {
      if (version !== state.loadVersion || error.name === "AbortError") return;
      state.loading = false;
      state.loadController = null;
      state.collection = null;
      state.cases = [];
      state.caseMap = new Map();
      state.filtered = [];
      state.selectedId = null;
      ui.summary.textContent = "未能读取所选测试集合";
      ui.retry.hidden = false;
      if (!state.collections.length) ui.collection.replaceChildren(new Option("集合加载失败", ""));
      setStatus(`${error.message} 请重试或选择其他集合。`, "error");
      render();
      return false;
    }
  }

  ui.form.addEventListener("submit", (event) => { event.preventDefault(); startBatch(state.filtered.map((item) => item.id)); });
  ui.saveDefaults.addEventListener("click", () => {
    if (state.running) return;
    const connection = readConnection();
    if (!connection) return;
    try {
      localStorage.setItem(DEFAULTS_KEY, JSON.stringify(connection));
      ui.defaultsStatus.textContent = "已保存 API 地址和模型名称，下次打开时自动使用。";
    } catch {
      ui.defaultsStatus.textContent = "保存失败，请检查浏览器是否允许本地存储。";
    }
  });
  ui.run.addEventListener("click", () => startBatch(state.filtered.map((item) => item.id)));
  ui.runCollections.addEventListener("click", () => startQueue(state.collections
    .filter((item) => state.selectedCollections.has(item.id))
    .map((item) => ({ collection_id: item.id, ids: null }))));
  ui.selectCollections.addEventListener("click", () => {
    if (state.running) return;
    state.selectedCollections = new Set(state.collections.map((item) => item.id));
    renderCollectionControls();
  });
  ui.clearCollections.addEventListener("click", () => {
    if (state.running) return;
    state.selectedCollections.clear();
    renderCollectionControls();
  });
  ui.single.addEventListener("click", () => { if (state.selectedId) startBatch([state.selectedId]); });
  ui.stop.addEventListener("click", () => {
    if (!state.running) return;
    state.stopRequested = true;
    setStatus(state.inFlight ? "已请求停止。正在等待当前请求完成，后续用例不会继续发送。" : "已请求停止，后续用例不会继续发送。", "running");
    renderControls();
  });
  ui.search.addEventListener("input", applyFilters);
  ui.language.addEventListener("change", applyFilters);
  ui.cwe.addEventListener("change", applyFilters);
  ui.clear.addEventListener("click", () => { ui.search.value = ""; ui.language.value = ""; ui.cwe.value = ""; applyFilters(); });
  ui.model.addEventListener("input", renderDetail);
  ui.proxyMode.addEventListener("change", renderControls);
  for (const eventName of ["input", "change"]) ui.form.addEventListener(eventName, (event) => {
    state.dirtyConfig.add(event.target.id);
    if ([ui.endpoint, ui.model].includes(event.target)) ui.defaultsStatus.textContent = "API 或模型名称已修改，点击“保存为默认”可保留。";
  });
  ui.collection.addEventListener("change", () => loadDataset(ui.collection.value));
  ui.retry.addEventListener("click", () => loadDataset());
  for (const tab of ui.tabs) {
    tab.addEventListener("click", () => { state.tab = tab.dataset.tab; renderDetail(); });
    tab.addEventListener("keydown", (event) => {
      const index = ui.tabs.indexOf(tab);
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % ui.tabs.length;
      else if (event.key === "ArrowLeft") next = (index + ui.tabs.length - 1) % ui.tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = ui.tabs.length - 1;
      else return;
      event.preventDefault();
      state.tab = ui.tabs[next].dataset.tab;
      renderDetail();
      ui.tabs[next].focus();
    });
  }
  ui.copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(ui.preview.textContent);
      ui.copy.textContent = "已复制";
    } catch { ui.copy.textContent = "请手动复制"; }
    window.setTimeout(() => { ui.copy.textContent = "复制"; }, 1800);
  });
  ui.requests.addEventListener("click", () => {
    if (state.loading || !state.collection || !state.filtered.length) return;
    const lines = state.filtered.map((item) => JSON.stringify(requestBody(item))).join("\n") + "\n";
    download(`decision-requests-${state.collection.id}-${state.filtered.length}.jsonl`, lines, "application/x-ndjson;charset=utf-8");
  });
  ui.results.addEventListener("click", () => {
    if (state.running || state.loading || !state.batch || !state.results.size) return;
    const rows = state.batch.ids.filter((id) => state.results.has(id)).map((id) => exportableResult(state.results.get(id)));
    download(`decision-results-${state.batch.collection_id}-${rows.length}.jsonl`, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "application/x-ndjson;charset=utf-8");
  });
  ui.metrics.addEventListener("click", () => {
    if (state.running || state.loading || !state.metrics || !state.batch) return;
    const report = { ...state.metrics, run: { collection_id: state.batch.collection_id, collection_name: state.batch.collection.name, request_profile: state.batch.collection.request_profile, case_ids: state.batch.ids, model: state.batch.config.model, endpoint: state.batch.config.endpoint, threshold: state.batch.config.threshold, timeout: state.batch.config.timeout, proxy_mode: state.batch.config.proxy_mode, context_limit_tokens: state.batch.context_limit_tokens, started_at: state.batch.started_at, finished_at: state.batch.finished_at } };
    download(`decision-metrics-${state.batch.collection_id}.json`, JSON.stringify(redactSecrets(report), null, 2) + "\n", "application/json;charset=utf-8");
  });
  ui.retryHistory.addEventListener("click", retryPendingHistory);
  ui.refreshHistory.addEventListener("click", async () => {
    if (state.historyBusy) return;
    state.historyBusy = true;
    renderHistory();
    try { await loadHistory(); }
    finally { state.historyBusy = false; renderHistory(); }
  });
  ui.downloadHistory.addEventListener("click", async () => {
    if (state.historyBusy) return;
    state.historyBusy = true;
    renderHistory();
    try {
      if (await loadHistory()) download("decision-run-history.json", JSON.stringify(state.history, null, 2) + "\n", "application/json;charset=utf-8");
    } finally {
      state.historyBusy = false;
      renderHistory();
    }
  });
  window.addEventListener("beforeunload", (event) => {
    if (!state.running && !state.pendingHistory.size) return;
    event.preventDefault();
    event.returnValue = "";
  });
  restoreDefaults();
  restorePendingHistory();
  loadDataset();
  retryPendingHistory();
})();
