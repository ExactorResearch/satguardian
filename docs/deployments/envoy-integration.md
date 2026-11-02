# Kubernetes & Envoy Proxy Integration Guide (Native Sidecar Pattern)

**Deployment Architecture:** On-premise edge inspection (lab configuration)  
**Codebase Reference:** `src/proxy/envoy_grpc.rs`, `k8s/envoy-sidecar-deployment.yaml`

> **Status: research prototype.** This guide describes an integration that has
> been exercised in a lab, not a production rollout. See [STATUS.md](../status.md).

---

## 1. Overview: Sub-Millisecond Sidecar Inspection

For high-throughput Kubernetes microservices and service meshes (Istio / Envoy), **SATGuardian Edge WAF** deploys as a lightweight, 100% self-contained native Rust sidecar container alongside each Envoy proxy pod.

 Envoy delegates incoming HTTP request authorization to the local SATGuardian daemon via the `ext_authz` filter over an in-memory **Unix Domain Socket** (`unix:///run/satguardian/waf.sock`) or loopback gRPC/HTTP socket, avoiding external network hops.

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

### Why the Native Rust Sidecar Pattern Excels
1. **Microsecond-Scale Engine Evaluation:** `satguardian-waf benchmark -r 10000`
   measures in-memory lexical and bitmask evaluation at roughly `20 µs` p50 and
   `22 µs` mean, with p99 fluctuating around `50 µs` depending on load. These
   numbers exclude the UDS hop, Envoy itself and the upstream service; end-to-end
   sidecar latency has not been characterized.
2. **100% Traffic Sovereignty & Zero Per-Request Cost:** All HTTP payloads stay strictly inside your Kubernetes cluster. There is zero external DNS CNAME routing, zero third-party traffic inspection, and **$0.00 cost per request**.
3. **Lock-Free Atomic Rule Updates (`ArcSwap`):** When the offline advisor or SATGuardian Cloud synthesizes a minimized `u128` rule matrix (consuming Security Units, SU), the sidecar hot-reloads the compiled bitmasks in memory via `ArcSwap` without restarting pods or dropping connections.
4. **Fail-Safe Continuity:** If the organization's monthly Security Units (SU) balance is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud rule synthesis pauses while every Kubernetes sidecar continues inspecting and blocking attacks indefinitely using its last compiled rule matrix.

---

## 2. Envoy `ext_authz` Configuration (`envoy.yaml`)

Configure Envoy's `envoy.filters.http.ext_authz` filter to forward request headers and bounded body payloads to the local SATGuardian sidecar:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      with_request_body:
        max_request_bytes: 8192
        allow_partial_message: true
        pack_as_bytes: true
      failure_mode_allow: false
      grpc_service:
        envoy_grpc:
          cluster_name: satguardian_ext_authz_cluster
        timeout: 0.05s

clusters:
  - name: satguardian_ext_authz_cluster
    type: STATIC
    connect_timeout: 0.01s
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: satguardian_ext_authz_cluster
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  pipe:
                    path: /run/satguardian/waf.sock
```

---

## 3. Kubernetes Deployment Manifest (`k8s/envoy-sidecar-deployment.yaml`)

Mount an in-memory `emptyDir` (`medium: Memory`) at `/run/satguardian` so Envoy and the `satguardian-waf` sidecar communicate over a shared RAM-backed Unix Domain Socket:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-api-protected
  labels:
    app: payment-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      volumes:
        - name: satguardian-uds
          emptyDir:
            medium: Memory
      containers:
        - name: satguardian-waf-sidecar
          image: ghcr.io/satguardian/satguardian-waf:v0.2.0
          args:
            - "proxy"
            - "--uds"
            - "/run/satguardian/waf.sock"
          resources:
            requests:
              cpu: "100m"
              memory: "64Mi"
            limits:
              cpu: "500m"
              memory: "128Mi"
          volumeMounts:
            - name: satguardian-uds
              mountPath: /run/satguardian

        - name: envoy-front-proxy
          image: envoyproxy/envoy:v1.29-latest
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: satguardian-uds
              mountPath: /run/satguardian
```

---

## 4. Measurement Summary

| Measurement | Source | Result |
| :--- | :--- | :--- |
| In-memory rule latency | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load |
| Detection, pinned corpus | `corpus/independent_v1.json` | 63/63 attacks, 0/16 benign blocked (in-sample regression) |
| Detection, first run before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Memory footprint | not measured in this repository | — |

No sidecar-to-vendor comparison is reported. Coraza, SafeLine and ModSecurity
have not been run in this environment; the Python harness agents that resemble
them are local stand-ins. See [STATUS.md](../status.md).
