# Kubernetes & Envoy Proxy Integration Guide (Native Sidecar Pattern, Lab Configuration)

**Deployment Architecture:** self-hosted edge inspection (lab configuration)  
**Codebase Reference:** `src/envoy/ext_authz.rs`, `envoy/envoy-uds.yaml`, `envoy/kubernetes-sidecar.yaml`

> **Status: research prototype.** This integration has been exercised in a lab on
> our own machine. It has not been run under real traffic, and nothing here is
> production evidence. See [STATUS.md](../status.md).

---

## 1. Overview: Sidecar Authorization in a Lab Pod

For Kubernetes workloads and service meshes (Istio / Envoy), **SATGuardian Edge WAF** can run as a small self-contained Rust sidecar container next to the Envoy proxy in the same pod.

Envoy delegates incoming HTTP request authorization to the local SATGuardian daemon via the `ext_authz` filter over an in-memory **Unix Domain Socket** (`/var/run/satguardian/waf.sock`) or a loopback HTTP socket, avoiding a network hop.

```
                      ┌─────────────────────────── Kubernetes Pod ───────────────────────────┐
                      │                                                                      │
Incoming Traffic ────►│  [ Envoy Proxy ] ──(ext_authz UDS)──► [ SATGuardian Rust Sidecar ]   │
  (Ingress/Mesh)      │         │                               (~20 µs avg in-memory eval)  │
                      │         │ (HTTP 200 OK / Allow)                     │                │
                      │         ▼                                           ▼                │
                      │  [ Upstream App Container ]              [ Local waf_ledger.db ]     │
                      └──────────────────────────────────────────────────────────────────────┘
```

### Why the Sidecar Shape Is Interesting
1. **Microsecond-scale engine evaluation (in memory only):** `satguardian-waf benchmark -r 10000`
   measures in-memory lexical and bitmask evaluation at roughly `20 µs` p50 and
   `22 µs` mean, with p99 fluctuating around `50 µs` depending on load. These
   numbers exclude the UDS hop, Envoy itself and the upstream service; end-to-end
   sidecar latency has not been characterized.
2. **Traffic stays inside your cluster, and the edge costs nothing per request:** all HTTP payloads are inspected locally, with no external DNS CNAME routing and no per-request fee. With the shipped defaults (`auto_sync_enabled = false` in `waf_config.toml`) the sidecar makes no outbound call at all.
3. **Rule updates are an operator decision, not a sync side effect:** cloud review returns clauses that are stored in the ledger as proposals (`dynamic_clauses.applied = 0`); the sync never touches the running engine. Approval is a separate action — `satguardian-waf clauses apply <id>` against the ledger, or an admin-token `POST /api/waf/clauses/{id}/apply` on the management API, which additionally registers the clause in the live process so subsequent requests see it without restarting the pod or dropping connections.
4. **Continuity if the cloud is not there:** if the monthly Security Units (SU) quota is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`) or `satguardian.tech` is unreachable, no new proposals arrive. Every sidecar keeps inspecting and blocking with the rule set it already has, because enforcement is entirely local.

---

## 2. Envoy `ext_authz` Configuration (`envoy/envoy-uds.yaml`)

The daemon in `src/envoy/ext_authz.rs` serves the ext_authz **HTTP** service (it answers a plain HTTP check request with `200` or `403`), so Envoy is configured with `http_service`, not `grpc_service`. The snippet below is the configuration shipped in this repository:

```yaml
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              http_service:
                server_uri:
                  uri: "http://unix/ext_authz"
                  cluster: satguardian_waf_uds
                  timeout: 0.25s
                authorization_request:
                  allowed_headers:
                    patterns:
                    - exact: "authorization"
                    - exact: "cookie"
                    - exact: "x-forwarded-for"
                    - exact: "user-agent"
                    - exact: "content-type"
                    - prefix: "x-"
              with_request_body:
                max_request_bytes: 65536
                pack_as_bytes: false
                allow_partial_message: true

clusters:
  - name: satguardian_waf_uds
    connect_timeout: 0.25s
    load_assignment:
      cluster_name: satguardian_waf_uds
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  pipe:
                    path: /var/run/satguardian/waf.sock
```

> The sidecar terminates nothing: TLS is expected to end at Envoy. `src/envoy/ext_authz.rs` reads the original method and path from `x-envoy-original-method` / `x-envoy-original-path` when Envoy forwards them, and only trusts `X-Forwarded-For` from proxies listed in `trusted_proxies`.

---

## 3. Kubernetes Sidecar Manifest (`envoy/kubernetes-sidecar.yaml`)

The committed manifest mounts an `emptyDir` with `medium: Memory` so Envoy and the sidecar share one Unix Domain Socket, and starts the daemon in `ext_authz` mode:

```yaml
      volumes:
        - name: satguardian-ipc
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
        - name: satguardian-ledger
          emptyDir: {}

      containers:
        - name: envoy-proxy
          image: envoyproxy/envoy:v1.30-latest
          args: ["-c", "/etc/envoy/envoy.yaml"]
          volumeMounts:
            - name: envoy-config-vol
              mountPath: /etc/envoy
            - name: satguardian-ipc
              mountPath: /var/run/satguardian

        - name: satguardian-waf-sidecar
          image: satguardian/satguardian-waf:v0.3.0
          command: ["/usr/local/bin/satguardian-waf"]
          args:
            - "envoy-authz"
            - "--socket"
            - "/var/run/satguardian/waf.sock"
          env:
            - name: WAF_MODE
              value: "block"
            - name: SATGUARDIAN_API_URL
              value: "https://satguardian.tech/api/simplify"
            - name: SATGUARDIAN_API_KEY            # optional; only needed for cloud review
              valueFrom:
                secretKeyRef:
                  name: satguardian-cloud-credentials
                  key: api-token
                  optional: true
            - name: WAF_DATABASE_PATH
              value: "/var/lib/satguardian/waf_ledger.db"
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "1"
              memory: "512Mi"
          volumeMounts:
            - name: satguardian-ipc
              mountPath: /var/run/satguardian
            - name: satguardian-ledger
              mountPath: /var/lib/satguardian
```

Two operational notes, both read straight off `src/main.rs`:

- **The ledger volume is `emptyDir` in the shipped manifest**, so recorded traffic, patterns awaiting analysis and open proposals disappear with the pod. Persist `/var/lib/satguardian` on a real volume before treating the ledger as an audit record.
- **`envoy-authz` is a pure verifier.** It mounts only the `ext_authz` router: no management API, and it starts from the compiled-in rule matrix rather than calling `load_applied_clauses()`, so a proposal you approve against that ledger does not silently become policy in the sidecar. If you want approved dynamic clauses *and* the approval API in one process, run the `proxy` command with `envoy_ext_authz_addr` (TCP, e.g. loopback) and `admin_listen_addr` set: `run_server` loads approved clauses (`applied = 1`) at startup and serves `POST /api/waf/clauses/{id}/apply` for live registration. The Unix Domain Socket path (`--socket`) exists only in `envoy-authz` today. Treat that split as a known limitation of the lab wiring, not as a hot-reload feature.

---

## 4. Measurement Summary

| Measurement | Source | Result |
| :--- | :--- | :--- |
| In-memory rule latency | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load; in-memory only |
| Detection, pinned corpus | `corpus/independent_v1.json` | 63/63 attacks, 0/16 benign blocked (**in-sample regression floor**) |
| Detection, first run before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| **Held-out detection (current engine)** | `benchmarks/real_comparative/corpus/heldout_v10.jsonl` | current engine **100% recall / 0.0% FPR** (post-tuning diagnostic); frozen one-shot **38.6% recall / 0.0% FPR**; earlier `heldout_v2` 56.1%/7.0% kept for provenance |
| End-to-end sidecar latency | not measured in this repository | — |
| Memory footprint | not measured in this repository | — |

No sidecar-to-vendor comparison is reported. Coraza, SafeLine and ModSecurity
have not been run in this environment; the Python harness agents that resemble
them are local stand-ins. There is no third-party evaluation of any of these
numbers. See [STATUS.md](../status.md).
