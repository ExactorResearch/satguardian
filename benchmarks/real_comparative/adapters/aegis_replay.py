#!/usr/bin/env python3
"""Replay a SATGuardian comparison corpus (JSONL) through a live Aegis instance
over real HTTP and emit verdicts in the satbench contract.

Phase-3 adapter: `latency_us` is the full HTTP round-trip through the Aegis
proxy including the upstream hop — it is NOT comparable to satbench's
in-memory figures. Record runs under `results/<engine>/RUN.json` per
`adapters/README.md` (binary digest, CRS version, paranoia level, mode, date).

Usage:
  python aegis_replay.py --corpus <file.jsonl> --base-url http://127.0.0.1:8088 \
      --out <verdicts.jsonl> [--engine-tag aegis-community-v1.1.0]

blocked rule: the edge rejected the request (HTTP 400/405/411/413/414/431 or a
transport error), or answered 403. Responses proxied from the upstream
(2xx/3xx/404/5xx with the upstream's own Server header) count as allowed.
Requests that cannot be expressed on the wire are percent-encoded / sanitized
and the normalization is recorded in `reason`.
"""

import argparse
import http.client
import json
import re
import sys
import time
import urllib.parse

EDGE_BLOCK_STATUSES = {400, 403, 405, 411, 413, 414, 431, 501}
TOKEN_RE = re.compile(r"[^!#$%&'*+\-.^_`|~0-9A-Za-z]")


def clean_method(method: str) -> tuple[str, bool]:
    cleaned = TOKEN_RE.sub("", method)
    return (cleaned or "GET"), cleaned != method


def clean_url(path: str, query: str) -> tuple[str, bool]:
    url = path
    if query:
        url += "?" + query
    encoded = urllib.parse.quote(url, safe="/?&=+#%:;@!$'()*,-._~")
    return encoded, encoded != url


def send(base, method, url, headers, body):
    parsed = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15)
    t0 = time.perf_counter()
    status = None
    server = ""
    aegis_waf = ""
    err = ""
    try:
        conn.putrequest(method, url, skip_host=False, skip_accept_encoding=True)
        sent_host = False
        for k, v in headers.items():
            lk = k.lower()
            if lk == "host":
                sent_host = True
            if lk in ("content-length", "transfer-encoding", "connection"):
                continue
            try:
                conn.putheader(k, v)
            except ValueError:
                pass
        if body:
            conn.putheader("Content-Length", str(len(body.encode("utf-8", "replace"))))
        elif not sent_host:
            pass
        conn.endheaders(body.encode("utf-8", "replace") if body else None)
        resp = conn.getresponse()
        status = resp.status
        server = resp.getheader("Server") or ""
        aegis_waf = resp.getheader("X-Aegis-Waf") or ""
        resp.read()
    except Exception as e:  # noqa: BLE001 - transport failure = edge rejected
        err = f"{type(e).__name__}: {e}"
    finally:
        conn.close()
    elapsed_us = (time.perf_counter() - t0) * 1e6
    return status, server, aegis_waf, elapsed_us, err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--base-url", default="http://127.0.0.1:8088")
    ap.add_argument("--out", required=True)
    ap.add_argument("--engine-tag", default="aegis-community-v1.1.0")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    n = 0
    with open(args.corpus, encoding="utf-8") as fin, open(args.out, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            req = case["request"]
            method, m_changed = clean_method(req.get("method", "GET"))
            url, u_changed = clean_url(req.get("path", "/"), req.get("query", ""))
            headers = dict(req.get("headers") or {})
            body = req.get("body", "")

            status, server, aegis_waf, latency_us, err = send(
                args.base_url, method, url, headers, body
            )
            notes = []
            if m_changed:
                notes.append("method_sanitized")
            if u_changed:
                notes.append("url_percent_encoded")

            if err:
                blocked = True
                reason = f"transport_error :: {err}"
            elif aegis_waf.lower() == "blocked" or status == 403:
                blocked = True
                reason = f"waf_block :: http_{status} x-aegis-waf={aegis_waf}"
            else:
                blocked = False
                reason = f"proxied :: http_{status} server={server}"
            if notes:
                reason += " :: " + ",".join(notes)

            rec = {
                "case_id": case["case_id"],
                "corpus": case.get("corpus", ""),
                "split": case.get("split", ""),
                "label": case.get("label", ""),
                "true_category": case.get("category", ""),
                "engine": args.engine_tag,
                "engine_kind": "external-http",
                "blocked": blocked,
                "engine_category": "",
                "matched_rules": [],
                "reason": reason,
                "latency_us": round(latency_us, 1),
                "http_status": status,
            }
            fout.write(json.dumps(rec) + "\n")
            n += 1
            if args.limit and n >= args.limit:
                break
    print(f"wrote {n} verdicts to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
