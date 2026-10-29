"""HTTP Request Payload and Attack Category Representations."""

from __future__ import annotations

import re
import uuid
import json
import urllib.parse
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


class AttackCategory(str, Enum):
    BENIGN = "benign"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    UNKNOWN = "unknown"

    # Aliases
    CROSS_SITE_SCRIPTING = "xss"
    REMOTE_CODE_EXECUTION = "command_injection"


class AttackDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass
class HTTPRequestPayload:
    """Represents an incoming HTTP request inspected by the WAF."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    method: str = "GET"
    path: str = "/api/v1/resource"
    query_string: str = ""
    query_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    expected_category: AttackCategory = AttackCategory.BENIGN
    ground_truth: Optional[AttackCategory] = None
    is_obfuscated: bool = False
    obfuscation_type: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Sync ground_truth and expected_category
        if self.ground_truth is not None and self.expected_category == AttackCategory.BENIGN and self.ground_truth != AttackCategory.BENIGN:
            self.expected_category = self.ground_truth
        elif self.ground_truth is None:
            self.ground_truth = self.expected_category

        # Reconstruct query_string if empty and query_params given
        if not self.query_string and self.query_params:
            self.query_string = urllib.parse.urlencode(self.query_params)
        elif self.query_string and not self.query_params:
            try:
                parsed = urllib.parse.parse_qs(self.query_string, keep_blank_values=True)
                self.query_params = {k: v[0] if len(v) == 1 else ",".join(v) for k, v in parsed.items()}
            except Exception:
                pass

        if "%" in self.path or "%" in self.query_string or "%" in self.body or "/**/" in self.query_string:
            self.is_obfuscated = True

    @property
    def is_malicious(self) -> bool:
        return self.expected_category != AttackCategory.BENIGN and self.expected_category != AttackCategory.UNKNOWN

    @property
    def headers_str(self) -> str:
        return " ".join(f"{k}: {v}" for k, v in self.headers.items())

    @property
    def normalized_text(self) -> str:
        """Returns decoded, normalized text representation of request targets."""
        raw = f"{self.path} {self.query_string} {self.body} {self.headers_str}"
        try:
            d1 = urllib.parse.unquote_plus(raw)
            d2 = urllib.parse.unquote_plus(d1) if "%" in d1 else d1
            if "/*" in d2:
                d2 = re.sub(r"/\*.*?\*/", " ", d2)
            return d2
        except Exception:
            return raw

    def get_full_inspectable_string(self) -> str:
        parts = [self.path]
        if self.query_string:
            parts.append(self.query_string)
        if self.body:
            parts.append(self.body)
        for k, v in self.headers.items():
            if k.lower() in ["user-agent", "cookie", "referer", "x-forwarded-for", "authorization"]:
                parts.append(f"{k}: {v}")
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name or self.description or self.id,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "query_params": self.query_params,
            "headers": self.headers,
            "body": self.body,
            "expected_category": self.expected_category.value,
            "ground_truth": self.ground_truth.value if self.ground_truth else self.expected_category.value,
            "is_obfuscated": self.is_obfuscated,
            "obfuscation_type": self.obfuscation_type,
            "description": self.description,
            "tags": self.tags
        }
