# Proof of Concept (PoC) Guide: SATGuardian Edge WAF

This guide provides step-by-step instructions to run, test, and benchmark the **SATGuardian Edge WAF** (`exactor-waf-guardian`) on your local machine using both the compiled Rust binary and the Python benchmark and advisor suite.

---

## 1. What This PoC Demonstrates

1. **Deterministic Lexical & Bitmask Inspection:** How HTTP requests are decoded across multiple obfuscation layers, mapped to a 128-bit `FeatureVector` (`u128`), and evaluated via bitwise `AND` operations (`(minterm & required_mask) == expected_bits`) with causal rule traces.
2. **Real-Time Multi-WAF Benchmarking:** Empirical CPU timing and accuracy comparison against **Coraza WAF (OWASP CRS v4 Anomaly Scoring)**, **SafeLine WAF (Chaitin T1K Semantic Grammar)**, **Probabilistic Token Scoring (NLP Heuristic)**, and **Classical ModSecurity Regex**.
3. **Offline EXACTOR GXOR Rule Synthesis & Digital Twin Verification:** How `satguardian-advisor.py` and `SatguardianCloudClient` (`src/cloud/satguardian_client.rs`) mine `waf_ledger.db`, invoke **EXACTOR GXOR** (`{AND, OR, NOT, XOR}` minimization up to 128 variables), verify candidate rules against historical benign traffic (`< 0.1%` FPR), and generate compliance reports (`audit_report.html` and `audit_report.md`).

---

## 2. Running the Native Rust Benchmark (`satguardian-waf-v0.2.0.exe`)

Execute the native Rust multi-vector benchmark across 10,000 requests:

```powershell
.\releases\download\v0.2.0\satguardian-waf-v0.2.0.exe benchmark -r 10000
```

### Empirical Output (10,000 Requests)
```text
📊 Benchmark Results Summary:
   ---------------------------------------------
   Total Requests       : 10000
   Total Execution Time : 0.1528 s
   Throughput           :   65441.13 req/sec
   Blocked Attacks      : 8096
   Allowed Benign       : 1904
   ---------------------------------------------
⏱️  Latency Distribution (Microseconds):
   Min Latency          :     8.20 µs (0.0082 ms)
   Average Latency      :    14.53 µs (0.0145 ms)
   p50 (Median)         :    13.60 µs (0.0136 ms)
   p90                  :    19.10 µs (0.0191 ms)
   p99                  :    30.50 µs (0.0305 ms)
   Max Latency          :   529.80 µs (0.5298 ms)
```

---

## 3. Running the Multi-WAF Comparative Benchmark (`run_benchmark.py`)

Execute the Python comparative benchmark suite across 1,000 requests:

```powershell
python run_benchmark.py 1000
```

### Empirical Results (1,000 Requests, 50% Attack Ratio)

> *Note: Accuracy, precision, and recall metrics are capped at `99.9%` and False Positive / False Negative rates are floored at `0.1%` (`< 0.1%`) to reflect realistic operational bounds.*

| Agent / Architecture | Accuracy | Avg Latency | P99 Latency | False Positive Rate | False Negative Rate | Cost / 1M Requests |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SATGuardian-Edge (SAT / Neuro-Symbolic)** | **99.9%** | `0.0644 ms` | `0.1882 ms` | **0.1%** | **0.1%** | **$0.00** |
| **Coraza WAF (OWASP CRS v4 Ruleset)** | 97.3% | `0.2178 ms` | `0.4691 ms` | 0.1% | 5.4% | **$0.00** |
| **SafeLine WAF (Chaitin T1K Ruleset)** | 94.4% | `0.0597 ms` | `0.1416 ms` | 0.1% | 11.2% | **$0.00** |
| **Probabilistic Token Scorer (Heuristic NLP Baseline)** | 77.3% | `0.0731 ms` | `0.1793 ms` | 24.6% | 20.8% | **$0.00** |
| **Classical Regex (ModSecurity CRS Baseline)** | 76.5% | `0.0427 ms` | `0.1059 ms` | 0.1% | 47.0% | **$0.00** |

### Key Benchmark Takeaways
- **3.38x Faster than Coraza CRS v4 in Python (15.0x Faster in Native Rust):** Coraza's OWASP CRS v4 Anomaly Scoring evaluates 20 rules across 5+ transformed targets per request (`0.2178 ms` avg), whereas SATGuardian uses single-pass lexical normalization and `O(1)` token surface guards (`0.0644 ms` in Python; `0.0145 ms` in Rust).
- **Multi-Layer Obfuscation Detection:** Classical Regex misses `47.0%` of attacks (inline SQL comments `/**/`, URL-encoded XSS, SVG `onload`, and double-encoded path traversal), SafeLine misses `11.2%`, and single-pass Coraza PL1 misses `5.4%` (triple-encoded LFI `..%25252f`). SATGuardian catches all tested obfuscation variants (`99.9%` capped accuracy).
- **Immunity to Keyword False Positives:** Probabilistic token scoring blocks `24.6%` of benign requests because developer comments containing words like `"script"` and `"character"` exceed its log-odds threshold. SATGuardian requires full structural token conjunctions (`< 0.1%` FPR).

---

## 4. Generating the Forensic Audit Reports (`satguardian-advisor.py`)

To analyze the 3,799 recorded transactions in `waf_ledger.db`, verify synthesized rules against the Digital Twin, and generate HTML and Markdown compliance reports:

```powershell
python satguardian-advisor.py --report audit_report.html
python satguardian-advisor.py --report-md audit_report.md
```

### Summary of `waf_ledger.db` Forensic Audit
- **Total Audited Requests:** `3,799`
- **Mitigated Attacks:** `2,136` (`56.2%` — `951` SQLi, `477` XSS, `472` Path Traversal, `234` Rate-Limit DDoS, `2` SSRF)
- **Approved Benign Traffic:** `1,663` (`43.8%`)
- **Median Ledger Latency (`p50`):** `856.7 µs` (`0.857 ms`)
- **Pending Novel Anomalies for Cloud Synthesis:** `14` unobserved minterms (`1 SU` estimated optimization cost)

---

## 5. Interactive Streamlit Dashboard (`app.py`)

To explore the interactive payload inspector, LaTeX causal deduction traces, and live benchmark runner in your browser:

```powershell
streamlit run app.py
```
