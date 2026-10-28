/**
 * SATGuardian Edge WAF - Frontend Application Logic
 */

let sampleDataset = [];
let allRules = [];
let latencyChart = null;
let costChart = null;
let duelActive = false;
let currentDuelIndex = 0;

document.addEventListener('DOMContentLoaded', async () => {
  await fetchSamples();
  await fetchRules();
  // Auto-run first sample for instant wow effect
  if (sampleDataset.length > 0) {
    loadSampleByIndex(0);
    runInspection();
  }
});

function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');
  
  const btn = document.getElementById(`btn-${tabId}`);
  if (btn) btn.classList.add('active');

  if (tabId === 'tab-benchmark' && !latencyChart) {
    runFullBenchmark();
  }
}

async function fetchSamples() {
  try {
    const res = await fetch('/api/waf/samples');
    const data = await res.json();
    if (data.status === 'ok') {
      sampleDataset = data.samples;
      populateSampleSelect();
    }
  } catch (err) {
    console.error('Failed to load samples:', err);
  }
}

function populateSampleSelect() {
  const sel = document.getElementById('sample-select');
  sel.innerHTML = '<option value="">-- Choose Sample Attack or Benign --</option>';
  sampleDataset.forEach((s, idx) => {
    const opt = document.createElement('option');
    opt.value = idx;
    const icon = s.expected_category === 'benign' ? '✅' : '🚨';
    opt.textContent = `${icon} [${s.expected_category.toUpperCase()}] ${s.name}`;
    sel.appendChild(opt);
  });
}

function loadSelectedSample() {
  const sel = document.getElementById('sample-select');
  const val = sel.value;
  if (val !== '') {
    loadSampleByIndex(parseInt(val, 10));
  }
}

function loadSampleByIndex(idx) {
  const s = sampleDataset[idx];
  if (!s) return;
  document.getElementById('inp-method').value = s.method;
  document.getElementById('inp-path').value = s.path;
  document.getElementById('inp-query').value = s.query_string;
  document.getElementById('inp-body').value = s.body;
  
  const badge = document.getElementById('traffic-category-badge');
  badge.textContent = `Ground Truth: ${s.expected_category.toUpperCase()}`;
  badge.className = `header-badge ${s.expected_category === 'benign' ? 'badge-emerald' : 'badge-red'}`;
}

function randomizePayload() {
  if (sampleDataset.length === 0) return;
  const randIdx = Math.floor(Math.random() * sampleDataset.length);
  document.getElementById('sample-select').value = randIdx;
  loadSampleByIndex(randIdx);
  runInspection();
}

async function runInspection() {
  const method = document.getElementById('inp-method').value;
  const path = document.getElementById('inp-path').value;
  const query = document.getElementById('inp-query').value;
  const body = document.getElementById('inp-body').value;

  const btn = document.getElementById('btn-run-inspect');
  btn.disabled = true;
  btn.innerHTML = '⏳ <span>Evaluating SAT Invariants...</span>';

  try {
    const res = await fetch('/api/waf/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method,
        path,
        query_string: query,
        body,
        headers: { 'User-Agent': 'Mozilla/5.0 (Security-Auditor)' }
      })
    });

    const data = await res.json();
    if (data.status === 'ok') {
      renderVerdictCards(data.agents);
      renderSATProof(data.agents.satguardian || data.agents.exactor);
    }
  } catch (err) {
    console.error('Inspection error:', err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🚀 <span>Inspect Payload Across All 3 Agents</span>';
  }
}

function renderVerdictCards(agents) {
  const container = document.getElementById('inspection-results-container');
  const satAgent = agents.satguardian || agents.exactor;
  container.innerHTML = `
    <div class="verdicts-container">
      ${renderSingleAgentCard(satAgent, '⚡ SATGuardian-Edge (SAT)', 'emerald')}
      ${renderSingleAgentCard(agents.jev_pure, '🤖 Pure JEV (Solo LLM Cloud)', 'amber')}
      ${renderSingleAgentCard(agents.regex, '📜 Classical ModSecurity Regex', 'blue')}
    </div>
  `;
}

function renderSingleAgentCard(agent, title, colorClass) {
  const isBlocked = agent.is_blocked;
  const statusBadge = isBlocked 
    ? `<span class="decision-badge blocked">🚫 BLOCKED (${agent.predicted_category.toUpperCase()})</span>`
    : `<span class="decision-badge allowed">✅ ALLOWED (BENIGN)</span>`;

  return `
    <div class="agent-verdict-card ${isBlocked ? 'blocked' : 'allowed'}">
      <div class="verdict-header">
        <span class="agent-title">${title}</span>
        ${statusBadge}
      </div>
      <div class="verdict-metrics-row">
        <span>⏱️ Latency: <strong>${agent.latency_ms} ms</strong></span>
        <span>💰 Cost: <strong>$${agent.cost_usd.toFixed(4)}</strong></span>
        <span>🎯 Confidence: <strong>${(agent.confidence * 100).toFixed(0)}%</strong></span>
      </div>
      <div class="verdict-explanation">
        ${agent.explanation}
      </div>
    </div>
  `;
}

function renderSATProof(satDecision) {
  const proofContainer = document.getElementById('proof-container');
  proofContainer.style.display = 'block';

  document.getElementById('proof-timing-badge').textContent = `⚡ Verified in ${satDecision.latency_ms} ms`;

  // Render active Certainty Islands
  const islandsList = document.getElementById('proof-islands-list');
  const activeIslands = satDecision.extra_metadata?.active_islands || [];
  if (islandsList) {
    islandsList.innerHTML = activeIslands.length > 0
      ? activeIslands.map(i => `<span class="island-chip">🏝️ ${i}</span>`).join('')
      : '<span class="island-chip island-chip-benign">🏝️ ISLAND-BENIGN (Whitelisted Grammar)</span>';
  }

  // Render tokens
  const tokenList = document.getElementById('proof-tokens-list');
  tokenList.innerHTML = satDecision.active_tokens.length > 0
    ? satDecision.active_tokens.map(t => `<span class="token-chip">${t}</span>`).join('')
    : '<span class="text-muted">No suspicious syntactic tokens extracted.</span>';

  // Render deduction steps
  const stepsList = document.getElementById('proof-steps-list');
  stepsList.innerHTML = `<li>${satDecision.explanation}</li>`;

  // Render KaTeX Math
  const katexBox = document.getElementById('katex-proof-box');
  if (satDecision.proof_latex && window.katex) {
    try {
      katex.render(satDecision.proof_latex, katexBox, {
        throwOnError: false,
        displayMode: true
      });
    } catch (e) {
      katexBox.textContent = satDecision.proof_latex;
    }
  } else {
    katexBox.textContent = "SAT Invariant holds: \\mathcal{L}_{\\text{Benign}} = \\text{TRUE}";
  }
}

/* ==========================================================================
   LIVE DUEL RACE LOGIC
   ========================================================================== */

async function startLiveDuel() {
  if (duelActive) return;
  duelActive = true;
  document.getElementById('btn-start-duel').disabled = true;
  document.getElementById('btn-stop-duel').disabled = false;

  // Reset counters
  let satStats = { count: 0, latSum: 0, cost: 0, correct: 0 };
  let jevStats = { count: 0, latSum: 0, cost: 0, correct: 0 };
  let regexStats = { count: 0, latSum: 0, cost: 0, correct: 0 };

  const totalSteps = 20;
  for (let i = 0; i < totalSteps; i++) {
    if (!duelActive) break;

    const sample = sampleDataset[i % sampleDataset.length];
    
    // Call inspect
    const res = await fetch('/api/waf/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: sample.method,
        path: sample.path,
        query_string: sample.query_string,
        body: sample.body,
        expected_category: sample.expected_category
      })
    });

    const data = await res.json();
    if (data.status === 'ok') {
      const { satguardian, exactor, jev_pure, regex } = data.agents;
      const satAgent = satguardian || exactor;

      // Update SATGuardian
      satStats.count++;
      satStats.latSum += satAgent.latency_ms;
      satStats.cost += satAgent.cost_usd;
      if (satAgent.is_correct) satStats.correct++;
      updateDuelLane('exactor', satStats, totalSteps, satAgent, sample);

      // Update JEV
      jevStats.count++;
      jevStats.latSum += jev_pure.latency_ms;
      jevStats.cost += jev_pure.cost_usd;
      if (jev_pure.is_correct) jevStats.correct++;
      updateDuelLane('jev', jevStats, totalSteps, jev_pure, sample);

      // Update Regex
      regexStats.count++;
      regexStats.latSum += regex.latency_ms;
      regexStats.cost += regex.cost_usd;
      if (regex.is_correct) regexStats.correct++;
      updateDuelLane('regex', regexStats, totalSteps, regex, sample);
    }

    await new Promise(r => setTimeout(r, 120));
  }

  stopLiveDuel();
}

function stopLiveDuel() {
  duelActive = false;
  document.getElementById('btn-start-duel').disabled = false;
  document.getElementById('btn-stop-duel').disabled = true;
}

function updateDuelLane(lanePrefix, stats, total, lastDecision, sample) {
  document.getElementById(`duel-${lanePrefix}-count`).textContent = `${stats.count} / ${total}`;
  const avgLat = (stats.latSum / stats.count).toFixed(lanePrefix === 'exactor' ? 3 : 1);
  document.getElementById(`duel-${lanePrefix}-lat`).textContent = `${avgLat} ms`;
  document.getElementById(`duel-${lanePrefix}-cost`).textContent = `$${stats.cost.toFixed(4)}`;
  const acc = Math.round((stats.correct / stats.count) * 100);
  document.getElementById(`duel-${lanePrefix}-acc`).textContent = `${acc}%`;

  const bar = document.getElementById(`duel-${lanePrefix}-bar`);
  bar.style.width = `${(stats.count / total) * 100}%`;

  const log = document.getElementById(`duel-${lanePrefix}-log`);
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  const icon = lastDecision.is_blocked ? '🚫 BLK' : '✅ ALW';
  entry.innerHTML = `<span>[#${stats.count}] ${icon} ${sample.expected_category.slice(0, 5)}</span><span>${lastDecision.latency_ms}ms</span>`;
  log.prepend(entry);
}

/* ==========================================================================
   FULL BENCHMARK SUITE & CHARTS
   ========================================================================== */

async function runFullBenchmark() {
  const samples = parseInt(document.getElementById('rng-samples').value, 10);
  const ratio = parseFloat(document.getElementById('rng-ratio').value);
  const btn = document.getElementById('btn-run-full-benchmark');

  btn.disabled = true;
  btn.innerHTML = '⏳ <span>Simulating Monte Carlo Streams...</span>';

  try {
    const res = await fetch('/api/waf/benchmark/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ num_requests: samples, attack_ratio: ratio })
    });

    const data = await res.json();
    if (data.status === 'ok') {
      renderBenchmarkTable(data.metrics);
      renderBenchmarkCharts(data.metrics);
      renderInsights(data.summary_insights);
    }
  } catch (err) {
    console.error('Benchmark run error:', err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '📊 <span>Execute Comparative Benchmark</span>';
  }
}

function renderBenchmarkTable(metrics) {
  const tbody = document.getElementById('benchmark-table-body');
  tbody.innerHTML = '';

  Object.entries(metrics).forEach(([name, m]) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${name}</strong></td>
      <td><span class="accent-emerald">${(m.accuracy * 100).toFixed(1)}%</span></td>
      <td>${(m.precision * 100).toFixed(1)}%</td>
      <td>${(m.recall * 100).toFixed(1)}%</td>
      <td>${(m.false_positive_rate * 100).toFixed(1)}%</td>
      <td><span class="${m.false_negative_rate > 0 ? 'accent-red' : ''}">${(m.false_negative_rate * 100).toFixed(1)}%</span></td>
      <td><strong>${m.avg_latency_ms.toFixed(3)} ms</strong></td>
      <td>${m.p99_latency_ms.toFixed(2)} ms</td>
      <td><strong>$${m.cost_per_million_usd.toFixed(2)}</strong></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderBenchmarkCharts(metrics) {
  const labels = Object.keys(metrics).map(k => k.split('(')[0].trim());
  const latencies = Object.values(metrics).map(m => m.avg_latency_ms);
  const costs = Object.values(metrics).map(m => m.cost_per_million_usd);

  // Latency Chart
  const ctxLat = document.getElementById('chart-latency').getContext('2d');
  if (latencyChart) latencyChart.destroy();
  latencyChart = new Chart(ctxLat, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Average Latency (ms)',
        data: latencies,
        backgroundColor: ['rgba(16, 185, 129, 0.7)', 'rgba(245, 158, 11, 0.7)', 'rgba(59, 130, 246, 0.7)'],
        borderColor: ['#10b981', '#f59e0b', '#3b82f6'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          type: 'logarithmic',
          title: { display: true, text: 'Latency in Milliseconds (Log Scale)', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        x: { grid: { display: false } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // Cost Chart
  const ctxCost = document.getElementById('chart-cost').getContext('2d');
  if (costChart) costChart.destroy();
  costChart = new Chart(ctxCost, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Cost per 1M Requests ($ USD)',
        data: costs,
        backgroundColor: ['rgba(16, 185, 129, 0.7)', 'rgba(239, 68, 68, 0.7)', 'rgba(59, 130, 246, 0.7)'],
        borderColor: ['#10b981', '#ef4444', '#3b82f6'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          title: { display: true, text: 'USD ($) per 1M Requests', color: '#94a3b8' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        x: { grid: { display: false } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderInsights(insights) {
  const container = document.getElementById('benchmark-insights-container');
  const list = document.getElementById('benchmark-insights-list');
  container.style.display = 'block';
  list.innerHTML = insights.map(i => `<li>${i}</li>`).join('');
}

/* ==========================================================================
   SAT RULES LEDGER
   ========================================================================== */

async function fetchRules() {
  try {
    const res = await fetch('/api/waf/rules');
    const data = await res.json();
    if (data.status === 'ok') {
      allRules = data.rules;
      renderRulesLedger(allRules);
    }
  } catch (err) {
    console.error('Failed to load rules:', err);
  }
}

function renderRulesLedger(rules) {
  const container = document.getElementById('rules-ledger-container');
  container.innerHTML = rules.map(r => `
    <div class="rule-card">
      <div class="rule-top">
        <span class="rule-id">${r.rule_id}</span>
        <span class="badge badge-emerald">${r.category}</span>
      </div>
      <div class="rule-name">${r.name}</div>
      <div class="rule-desc">${r.description}</div>
      <div class="rule-formula"><code>${r.invariant_formula}</code></div>
    </div>
  `).join('');
}

function filterRulesLedger() {
  const query = document.getElementById('rule-search-inp').value.toLowerCase();
  const filtered = allRules.filter(r => 
    r.rule_id.toLowerCase().includes(query) ||
    r.name.toLowerCase().includes(query) ||
    r.category.toLowerCase().includes(query) ||
    r.description.toLowerCase().includes(query)
  );
  renderRulesLedger(filtered);
}

/* ==========================================================================
   CONTACT / DEMO MODAL HANDLERS
   ========================================================================== */

function openContactModal() {
  const modal = document.getElementById('contactModal');
  if (modal) {
    modal.style.display = 'flex';
  }
}

function closeContactModal() {
  const modal = document.getElementById('contactModal');
  if (modal) {
    modal.style.display = 'none';
  }
}

function handleModalOverlayClick(e) {
  if (e.target && e.target.id === 'contactModal') {
    closeContactModal();
  }
}

async function submitContactForm(e) {
  e.preventDefault();
  const btn = document.getElementById('btnSubmitLead');
  const successBanner = document.getElementById('contactSuccessMsg');
  
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Registering Request...';
  }
  
  const leadData = {
    name: document.getElementById('leadName').value,
    email: document.getElementById('leadEmail').value,
    company_role: document.getElementById('leadCompanyRole').value,
    use_case: document.getElementById('leadUseCase').value
  };

  try {
    const res = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(leadData)
    });
    if (!res.ok) throw new Error('Network error');
  } catch (err) {
    console.warn('Inbound contact endpoint fallback:', err);
  }

  if (successBanner) {
    successBanner.style.display = 'block';
  }
  if (btn) {
    btn.textContent = '✓ Demo Request Received';
  }

  setTimeout(() => {
    window.location.href = `mailto:contact@exactor.tech?subject=Exactor%20WAF%20Guardian%20Demo%20Request:%20${encodeURIComponent(leadData.company_role)}&body=Full%20Name:%20${encodeURIComponent(leadData.name)}%0AWork%20Email:%20${encodeURIComponent(leadData.email)}%0ACompany%20and%20Role:%20${encodeURIComponent(leadData.company_role)}%0AUse%20Case:%20${encodeURIComponent(leadData.use_case)}`;
  }, 1200);
}

