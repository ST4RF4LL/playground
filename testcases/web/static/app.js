"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const ui = {
    summary: $("dataset-summary"), form: $("config-form"), endpoint: $("endpoint"),
    model: $("model"), apiKey: $("api-key"), threshold: $("threshold"), timeout: $("timeout"),
    proxyMode: $("proxy-mode"), proxySummary: $("proxy-summary"),
    collection: $("collection-selector"), collectionDescription: $("collection-description"), collectionProfile: $("collection-profile"),
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
  };
  const state = {
    cases: [], caseMap: new Map(), filtered: [], selectedId: null, tab: "request",
    running: false, stopRequested: false, inFlight: null, batch: null,
    results: new Map(), metrics: null, scoringError: null,
    collections: [], collection: null, requestedCollectionId: null, loading: false,
    loadVersion: 0, loadController: null, defaultsApplied: false, dirtyConfig: new Set(),
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
    return verdict === "vulnerable" ? "有漏洞" : verdict === "not_vulnerable" ? "无目标漏洞" : "无有效判断";
  }

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
    return state.running ? state.batch.config.model : ui.model.value.trim() || "jev-latest";
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
    return { label: result.verdict === "vulnerable" ? "误报 FP" : "漏报 FN", kind: "incorrect" };
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
      meta.append(makeTag(languageNames[item.language] || item.language), makeTag(item.focus_cwe));
      const expected = document.createElement("span");
      expected.className = `expected-mini${expectedVerdict(item) === "vulnerable" ? " positive" : ""}`;
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
    ui.detailId.textContent = item?.id || "CASE PREVIEW";
    ui.detailTitle.textContent = item?.title || "暂无选中的用例";
    ui.detailTags.replaceChildren();
    if (item) {
      ui.detailTags.append(makeTag(languageNames[item.language] || item.language), makeTag(item.focus_cwe));
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
      ui.previewNote.textContent = "源码来自当前用例；环境约定与漏洞范围可在请求 Body 的 state 中查看。";
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
        const name = result.verdict === "vulnerable" ? expected === "vulnerable" ? "tp" : "fp" : expected === "not_vulnerable" ? "tn" : "fn";
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
  }

  function renderControls() {
    for (const input of ui.form.querySelectorAll("input, select")) input.disabled = state.running;
    ui.proxySummary.textContent = ui.proxyMode.value === "system" ? "使用环境 / 系统代理" : "默认直连（不使用代理）";
    ui.collection.disabled = state.running || !state.collections.length;
    if (state.requestedCollectionId) ui.collection.value = state.requestedCollectionId;
    if (state.collection) {
      ui.collectionDescription.textContent = state.collection.description || state.collection.name;
      ui.collectionProfile.textContent = `${state.collection.count ?? state.cases.length} 条用例 · 切换集合会清空上批结果，保留连接配置。`;
    } else {
      const pending = state.collections.find((item) => item.id === state.requestedCollectionId);
      ui.collectionDescription.textContent = state.loading ? `正在加载${pending ? `「${pending.name}」` : "测试集合"}，完成后即可运行。` : "集合加载失败，当前没有可运行的数据。请重试或切换集合。";
      ui.collectionProfile.textContent = "连接配置保持不变；只有成功加载后才能运行与导出。";
    }
    for (const filter of [ui.search, ui.language, ui.cwe]) filter.disabled = state.loading || !state.cases.length;
    ui.run.disabled = state.running || state.loading || !state.collection || !state.filtered.length;
    ui.runLabel.textContent = state.loading ? "正在加载集合…" : state.running ? `运行中 ${state.results.size} / ${state.batch.ids.length}` : `运行当前用例 (${state.filtered.length})`;
    ui.run.title = "开始新批次，清空上批结果";
    ui.single.disabled = state.running || state.loading || !state.collection || !state.selectedId;
    ui.single.title = "以此用例开始新批次，清空上批结果";
    ui.stop.disabled = !state.running || state.stopRequested;
    ui.stop.textContent = state.stopRequested && state.running ? "等待当前请求…" : "■ 停止";
    ui.requests.disabled = state.loading || !state.collection || !state.filtered.length;
    ui.results.disabled = state.running || state.loading || !state.results.size;
    ui.metrics.disabled = state.running || state.loading || !state.metrics;
    ui.clear.hidden = !(ui.search.value || ui.language.value || ui.cwe.value);
  }

  function render() {
    renderList();
    renderDetail();
    renderMetrics();
    renderControls();
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

  function readConfig() {
    if (!ui.form.reportValidity()) return null;
    const endpoint = ui.endpoint.value.trim();
    const model = ui.model.value.trim();
    const threshold = Number(ui.threshold.value);
    const timeout = Number(ui.timeout.value);
    const proxy_mode = ui.proxyMode.value;
    let url;
    try { url = new URL(endpoint); } catch { setStatus("请填写完整的 API URL。", "error"); ui.endpoint.focus(); return null; }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
      setStatus("API URL 需要以 http:// 或 https:// 开头，鉴权信息请填入 API key。", "error");
      ui.endpoint.focus();
      return null;
    }
    if (!model) { setStatus("请填写模型名称。", "error"); ui.model.focus(); return null; }
    if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1 || !Number.isInteger(timeout) || timeout < 1 || timeout > 300) {
      setStatus("判定阈值应在 0–1 之间，超时应为 1–300 秒的整数。", "error");
      return null;
    }
    if (!["direct", "system"].includes(proxy_mode)) {
      setStatus("请选择有效的代理模式。", "error");
      ui.proxyMode.focus();
      return null;
    }
    return Object.freeze({ endpoint, api_key: ui.apiKey.value.trim(), model, threshold, timeout, proxy_mode });
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
    const config = readConfig();
    if (!config) return;
    state.running = true;
    state.stopRequested = false;
    state.batch = { ids: Object.freeze([...ids]), collection_id: state.collection.id, collection: Object.freeze({ ...state.collection }), config, started_at: new Date().toISOString(), finished_at: null };
    state.results.clear();
    state.metrics = null;
    state.scoringError = null;
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
          if (result.status === "ok" && (!["vulnerable", "not_vulnerable"].includes(result.verdict) || !Number.isFinite(result.score))) throw new Error("模型响应没有有效的判断或 noul 分值。");
        } catch (error) {
          result = { id, collection_id: state.batch.collection_id, status: "error", latency_ms: Math.round(performance.now() - started), error: error.message, raw_response: null };
        }
        state.results.set(id, redactSecrets(result, config.api_key));
        state.inFlight = null;
        render();
        await refreshScore();
      }
    } finally {
      state.running = false;
      state.inFlight = null;
      state.batch.finished_at = new Date().toISOString();
      const remaining = state.batch.ids.length - state.results.size;
      const errors = localCounts().errors;
      let message = remaining ? `已停止 · 已完成 ${state.results.size} / ${state.batch.ids.length} 条，${remaining} 条未执行。` : `本批完成 · ${state.results.size} 条用例，${errors} 条请求或解析错误。`;
      if (state.scoringError) message += ` 指标服务暂不可用：${state.scoringError}`;
      else message += " 可导出结果与详细指标。";
      setStatus(message, state.scoringError || errors ? "error" : "success");
      // Keep only non-secret batch metadata after the requests have finished.
      state.batch.config = Object.freeze({ endpoint: config.endpoint, model: config.model, threshold: config.threshold, timeout: config.timeout, proxy_mode: config.proxy_mode });
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
    for (const key of ["id", "collection_id", "status", "verdict", "score", "latency_ms", "http_status", "response_model", "error", "raw_response"]) {
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

  async function loadDataset(collectionId = state.requestedCollectionId) {
    if (state.running) return;
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
    state.stopRequested = false;
    state.results.clear();
    state.metrics = null;
    state.scoringError = null;
    ui.search.value = "";
    ui.language.replaceChildren(new Option("全部语言", ""));
    ui.cwe.replaceChildren(new Option("全部漏洞类别", ""));
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
      state.requestedCollectionId = data.collection.id;
      state.cases = cases;
      state.caseMap = caseMap;
      ui.collection.replaceChildren(...state.collections.map((item) => new Option(item.name, item.id)));
      ui.collection.value = state.collection.id;
      applyInitialDefaults(data.defaults || {});
      const languages = [...new Set(state.cases.map((item) => item.language))];
      const categories = [...new Set(state.cases.map((item) => item.focus_cwe))].sort((a, b) => a.localeCompare(b, "en", { numeric: true }));
      ui.language.replaceChildren(new Option("全部语言", ""), ...languages.map((language) => new Option(languageNames[language] || language, language)));
      ui.cwe.replaceChildren(new Option("全部漏洞类别", ""), ...categories.map((cwe) => new Option(`${cwe}${cweNames[cwe] ? ` · ${cweNames[cwe]}` : ""}`, cwe)));
      const positive = state.cases.filter((item) => expectedVerdict(item) === "vulnerable").length;
      ui.summary.textContent = `${state.collection.name} · ${state.cases.length} 条用例 · ${languages.length} 种语言 · ${categories.length} 类漏洞 · 有漏洞 ${positive} / 无目标漏洞 ${state.cases.length - positive}`;
      state.loading = false;
      state.loadController = null;
      applyFilters();
      setStatus(`「${state.collection.name}」已就绪。每次运行创建新批次，切换集合会清空结果并保留连接配置。`, "success");
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
    }
  }

  ui.form.addEventListener("submit", (event) => { event.preventDefault(); startBatch(state.filtered.map((item) => item.id)); });
  ui.run.addEventListener("click", () => startBatch(state.filtered.map((item) => item.id)));
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
  for (const eventName of ["input", "change"]) ui.form.addEventListener(eventName, (event) => state.dirtyConfig.add(event.target.id));
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
    const report = { ...state.metrics, run: { collection_id: state.batch.collection_id, collection_name: state.batch.collection.name, request_profile: state.batch.collection.request_profile, case_ids: state.batch.ids, model: state.batch.config.model, endpoint: state.batch.config.endpoint, threshold: state.batch.config.threshold, timeout: state.batch.config.timeout, proxy_mode: state.batch.config.proxy_mode, started_at: state.batch.started_at, finished_at: state.batch.finished_at } };
    download(`decision-metrics-${state.batch.collection_id}.json`, JSON.stringify(redactSecrets(report), null, 2) + "\n", "application/json;charset=utf-8");
  });
  loadDataset();
})();
