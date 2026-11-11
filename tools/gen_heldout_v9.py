#!/usr/bin/env python3
"""Generate heldout_v9.jsonl — clean held-out batch v9.

Families structurally absent from ALL v1-v8 tuning corpora and unified_v1:
cookie tossing / CRLF-in-cookie, path parameters (;jsessionid), Range and
conditional (If-*) header abuse, JSON \\uXXXX string escapes, HTML entity
evasion (&Tab;/&NewLine;/numeric refs), base64-encoded attack params,
compression bombs, GraphQL clairvoyance/field-suggestion probes, API
version downgrade paths, cache-purge verbs (PURGE/BAN), and trailer
smuggling.
"""
import json, hashlib

OUT = "benchmarks/real_comparative/corpus/heldout_v9.jsonl"

ATTACKS = {
 "cookie_tossing": [
  ("GET","/account","","",{"Cookie":"session=abc123; Domain=.evil.example; Path=/"}),
  ("GET","/account","","",{"Cookie":"session=abc123%0d%0aSet-Cookie:%20admin=1"}),
  ("GET","/account","","",{"Cookie":"prefs=theme%22%3B%20admin%3Dtrue"}),
  ("GET","/account","","",{"Cookie":"session=abc; HttpOnly; Secure; SameSite=None; Domain=evil.example"}),
  ("GET","/admin","","",{"Cookie":"session=../../etc/passwd"}),
  ("GET","/admin","","",{"Cookie":"session=' OR '1'='1"}),
  ("GET","/api/me","","",{"Cookie":"auth=eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."}),
  ("GET","/account","","",{"Cookie":"session=abc; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=.attacker.example"}),
 ],
 "path_parameters": [
  ("GET","/admin;jsessionid=ABCDEF1234567890","",""),
  ("GET","/api;/v1/users","",""),
  ("GET","/account;/settings","",""),
  ("GET","/api/v1/users;param=../../../etc/passwd","",""),
  ("GET","/login;jsessionid=<script>alert(1)</script>","",""),
  ("GET","/api/;/actuator/env","",""),
  ("GET","/admin%3bjsessionid%3dABC","",""),
  ("GET","/search;x=1' OR '1'='1","",""),
 ],
 "range_header": [
  ("GET","/api/file","","",{"Range":"bytes=0-99999999999"}),
  ("GET","/api/file","","",{"Range":"bytes=-999999999"}),
  ("GET","/api/file","","",{"Range":"bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19,20-21"}),
  ("GET","/api/file","","",{"Range":"bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10"}),
  ("GET","/api/file","","",{"Range":"items=0-100"}),
  ("GET","/api/file","","",{"Range":"bytes=999999999999-"}),
 ],
 "conditional_headers": [
  ("GET","/api/file","","",{"If":"<http://evil.example/x> (<urn:uuid:1234>)"}),
  ("GET","/api/file","","",{"If-Match":"*; Delete"}),
  ("GET","/api/file","","",{"If-Modified-Since":"<script>alert(1)</script>"}),
  ("GET","/api/file","","",{"If-None-Match":"W/\"../../../etc/passwd\""}),
  ("GET","/api/file","","",{"If-Range":"http://evil.example/x"}),
  ("GET","/api/file","","",{"If-Unmodified-Since":"Thu, 01 Jan 1970 00:00:00 GMT; boundary=--"}),
 ],
 "json_unicode": [
  ("POST","/api/search","",'{"q":"\\u0027 OR 1=1--"}'),
  ("POST","/api/search","",'{"q":"\\u0075nion \\u0073elect password"}'),
  ("POST","/api/data","",'{"x":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'),
  ("POST","/api/search","",'{"q":"admin\\u0027--"}'),
  ("POST","/api/search","",'{"q":"1\\u0027 UNION SELECT password FROM users--"}'),
  ("POST","/api/data","",'{"x":"\\u002e\\u002e\\u002f\\u002e\\u002e\\u002fetc\\u002fpasswd"}'),
  ("POST","/api/search","",'{"q":"\\u0027; DROP TABLE users;--"}'),
  ("POST","/api/data","",'{"x":"javascript\\u003aalert(1)"}'),
 ],
 "html_entity": [
  ("GET","/search","q=%26%23x27%3B%20OR%201%3D1--",""),
  ("GET","/search","q=%26Tab%3B%26NewLine%3B%3Cscript%3Ealert(1)%3C%2Fscript%3E",""),
  ("GET","/search","q=&apos; OR 1=1--",""),
  ("GET","/search","q=%26%23x3C%3Bimg%20src%3Dx%20onerror%3Dalert(1)%26%23x3E%3B",""),
  ("GET","/search","q=1%26%23039%3B%20OR%201%3D1",""),
  ("GET","/search","q=%26%23X55%3B%26%23X4E%3B%26%23X49%3B%26%23X4F%3B%26%23X4E%3B",""),
  ("GET","/search","q=%26colon%3Balert(1)",""),
  ("GET","/search","q=javas%26%23x63%3Bript%3Aalert(1)",""),
 ],
 "base64_param": [
  ("GET","/api/decode","q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",""),
  ("GET","/api/decode","q=JyBPUiAxPTEtLQ==",""),
  ("GET","/api/decode","q=Li4vLi4vZXRjL3Bhc3N3ZA==",""),
  ("GET","/api/decode","q=U1lTVEVNKCJpZCIp",""),
  ("GET","/api/decode","q=U0VMRUNUIHBhc3N3b3JkIEZST00gdXNlcnM=",""),
  ("GET","/api/decode","q=ezZvbmNsaWNreTogamF2YS5sYW5nLlJ1bnRpbWV9",""),
  ("POST","/api/blob","",'{"data":"PD94bWwgdmVyc2lvbj0iMS4wIj8+PCFET0NUWVBFIHJbPCFFTlRJVFkgeCBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI+XT48cj4meDs8L3I+"}'),
  ("GET","/api/decode","q=__import__('os').system('id')",""),
 ],
 "compression_bomb": [
  ("POST","/api/upload","",'\x1f\x8b\x08\x00'+'A'*100000,{"Content-Type":"application/gzip","Content-Encoding":"gzip"}),
  ("POST","/api/upload","",'x'*500000,{"Content-Type":"application/octet-stream","Content-Encoding":"deflate","Content-Length":"500000"}),
  ("POST","/api/upload","",'\x78\x9c'+'B'*200000,{"Content-Encoding":"br"}),
  ("POST","/api/data","",'\x1f\x8b\x08\x00'+('C'*50000),{"Content-Encoding":"gzip"}),
  ("POST","/api/upload","",'PK\x03\x04'+('D'*100000),{"Content-Encoding":"compress"}),
  ("POST","/api/data","",'\x04\x22\x4d\x18'+('E'*80000),{"Content-Encoding":"zstd"}),
 ],
 "graphql_clairvoyance": [
  ("POST","/graphql","",'{"query":"{ __typename user { __typename } }"}'),
  ("POST","/graphql","",'{"query":"{ user { email passwordHash ssn creditCard } }"}'),
  ("POST","/graphql","",'{"query":"query { a: user(id:1){id} b: user(id:2){id} c: user(id:3){id} d: user(id:4){id} }"}'),
  ("POST","/graphql","",'{"query":"{ user { ...F1 } } fragment F1 on User { email passwordHash role isAdmin }"}'),
  ("POST","/graphql","",'{"query":"mutation { deleteUser(id:1) }"}'),
  ("POST","/graphql","",'{"query":"{ __schema { types { name fields { name } } } }"}'),
  ("POST","/graphql","",'{"query":"{ nonexistentField12345 }"}'),
  ("POST","/graphql","",'{"query":"{ user(id:1) { id } user(id:2) { id } user(id:3) { id } user(id:4) { id } user(id:5) { id } }"}'),
 ],
 "api_version_abuse": [
  ("GET","/api/v0/admin/users","",""),
  ("GET","/api/v1/../v2/internal/debug","",""),
  ("GET","/api/internal/metrics","",""),
  ("GET","/api/v9/admin","",""),
  ("GET","/v0/api/users","",""),
  ("GET","/api/v1%2f..%2fv2%2fadmin","",""),
  ("GET","/api/beta/admin","",""),
  ("GET","/api/v1;debug=true/admin","",""),
 ],
 "purge_methods": [
  ("PURGE","/api/cache","",""),
  ("PURGE","/*","",""),
  ("BAN","/api/user/1","",""),
  ("LINK","/api/file","",'<http://evil.example/x>; rel="canonical"'),
  ("UNLINK","/api/file","",""),
  ("PROPFIND","/","",""),
 ],
 "trailer_smuggling": [
  ("POST","/api/data","",'chunk1',{"Transfer-Encoding":"chunked","Trailer":"Content-Length","Content-Length":"0"}),
  ("POST","/api/data","",'x',{"Transfer-Encoding":"chunked","Trailer":"Host, Content-Length"}),
  ("POST","/api/data","",'x=1',{"TE":"chunked","Trailer":"Transfer-Encoding"}),
  ("POST","/api/data","",'x',{"Transfer-Encoding":"chunked, identity"}),
  ("POST","/api/data","",'x',{"Transfer-Encoding":" chunked "}),
  ("POST","/api/data","",'x',{"Transfer-Encoding":"chunked","Trailer":"X-Evil: <?php phpinfo();?>"}),
 ],
}

BENIGN = [
 ("GET","/account","",""),
 ("GET","/account/settings","",""),
 ("GET","/api/user/42","",""),
 ("GET","/api/users","id=1&page=2",""),
 ("GET","/api/search","q=hello+world",""),
 ("GET","/api/search","q=select+*+from+products",""),   # SQL words in search — trap
 ("GET","/api/search","q=union+select+meaning",""),
 ("GET","/api/file","path=docs/report.pdf",""),
 ("GET","/api/file","name=invoice-2024.xlsx",""),
 ("GET","/static/style.css","",""),
 ("GET","/static/app.js","",""),
 ("GET","/img/photo.jpg","",""),
 ("GET","/api/v1/users","limit=10",""),
 ("GET","/api/v1/users","limit=10&offset=20",""),
 ("GET","/api/v2/items","?filter=active",""),
 ("GET","/api/v1/status","",""),
 ("GET","/api/docs","page=2",""),
 ("POST","/api/search","",'{"q":"coffee beans"}'),
 ("POST","/api/search","",'{"q":"what is union select in sql"}'),
 ("POST","/api/data","",'{"name":"José García","city":"Zürich"}'),
 ("POST","/api/data","",'{"text":"café ☕ naïve résumé"}'),
 ("POST","/api/data","",'{"q":"100% coverage","note":"save 50%"}'),
 ("POST","/api/data","",'{"path":"C:\\Users\\test\\file.txt"}'),
 ("POST","/api/data","",'{"msg":"use \\u0041 for A"}'),
 ("GET","/search","q=fish+%26+chips",""),
 ("GET","/search","q=AT%26T+plans",""),
 ("GET","/search","q=5+%3E+3",""),
 ("GET","/search","q=%3Cscript%3E+is+an+html+tag",""),   # entity-encoded words as topic — trap
 ("GET","/search","q=base64+encoding+explained",""),
 ("GET","/api/decode","q=aGVsbG8gd29ybGQ=",""),          # benign b64
 ("GET","/api/decode","q=dGVzdA==",""),
 ("GET","/api/items","tags=a,b,c",""),
 ("GET","/api/items","?sort=-price&order=desc",""),
 ("GET","/api/cart","?items=1,2,3",""),
 ("POST","/api/orders","",'{"items":[{"sku":"A1","qty":2}]}'),
 ("GET","/api/user","?fields=name,email",""),
 ("GET","/api/export","?format=csv",""),
 ("GET","/api/export","?format=pdf&range=1-5",""),
 ("GET","/api/report","?from=2024-01-01&to=2024-12-31",""),
 ("GET","/","x-custom-header=test",""),
 ("HEAD","/api/status","",""),
 ("OPTIONS","/api/data","",""),
 ("GET","/robots.txt","",""),
 ("GET","/favicon.ico","",""),
 ("GET","/api/health","",""),
 ("GET","/sitemap.xml","",""),
 ("POST","/api/notes","",'text=Meeting+at+5pm+discuss+%22union+select%22+article'),
]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out"):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v9",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": ("Frozen held-out batch v9: techniques absent from v1-v8 tuning."
                         if label == "malicious" else "Benign control written independently of engine internals."),
    }

notes = {c: f"v9 fresh techniques for {c}." for c in ATTACKS}
notes["benign"] = "Benign control v9."

cases=[]
for cat,payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        cases.append(mk(f"heldout_v9/{cat}-{i:02d}",cat,"malicious",notes[cat],m,p,q,b,rest[0] if rest else {}))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    cases.append(mk(f"heldout_v9/benign-{i:03d}","benign","benign",notes["benign"],m,p,q,b,rest[0] if rest else {}))

with open(OUT,"w",encoding="utf-8",newline="\n") as f:
    for c in cases: f.write(json.dumps(c,ensure_ascii=False)+"\n")
lines=[json.loads(l) for l in open(OUT,encoding="utf-8")]
sha=hashlib.sha256(open(OUT,"rb").read()).hexdigest()
for c in lines: c["corpus_sha256"]=sha
with open(OUT,"w",encoding="utf-8",newline="\n") as f:
    for c in lines: f.write(json.dumps(c,ensure_ascii=False)+"\n")
mal=[c for c in cases if c["label"]=="malicious"]; ben=[c for c in cases if c["label"]=="benign"]
print(f"wrote {len(cases)} cases -> {OUT}")
print(f"malicious={len(mal)} benign={len(ben)} sha256={sha[:16]}")
from collections import Counter
print(Counter(c["category"] for c in mal))
