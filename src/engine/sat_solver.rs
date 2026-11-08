use crate::ast::features::{FeatureBinarizer, FeatureVector};
use crate::ast::lexer::{AstLexer, LexicalTokens};
use crate::config::{BusinessRulesConfig, CustomBusinessRule, IslandsConfig};
use crate::stateful::StatefulVerdict;
use crate::types::{
    AttackCategory, AttackDecision, CertaintyIsland, DeductionRule, ExecutionPath,
    HttpRequestPayload, ProofChain,
};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Dynamic clause resulting from SATGuardian Cloud Minimization (`https://satguardian.tech/api/simplify`).
#[derive(Debug, Clone)]
pub struct DynamicCompiledClause {
    pub clause_id: String,
    pub description: String,
    pub required_mask: u128,
    pub expected_bits: u128,
    pub category: AttackCategory,
}

/// Deterministic Neuro-Symbolic & SAT Constraint Engine with Certainty Islands.
pub struct SatguardianSatEngine {
    islands: HashMap<String, CertaintyIsland>,
    rules: HashMap<String, DeductionRule>,
    dynamic_clauses: RwLock<Vec<DynamicCompiledClause>>,
    pub islands_config: RwLock<IslandsConfig>,
    pub business_rules_config: RwLock<BusinessRulesConfig>,
}

/// Backward compatibility alias for Exactor SAT Engine.
pub type ExactorSatEngine = SatguardianSatEngine;

impl Default for SatguardianSatEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Lower rank wins when a request matches multiple certainty islands.
fn category_specificity(category: AttackCategory) -> u8 {
    match category {
        AttackCategory::FrameworkExploitProbe => 0,
        AttackCategory::CmsWordpressProbe => 1,
        AttackCategory::SensitiveExposureProbe => 2,
        AttackCategory::JwtTampering => 3,
        AttackCategory::GrpcSmuggling => 4,
        AttackCategory::GraphqlAbuse => 5,
        AttackCategory::PrototypePollution => 6,
        AttackCategory::Ssti => 7,
        AttackCategory::NoSqlInjection => 8,
        AttackCategory::HostHeaderInjection => 9,
        AttackCategory::HttpResponseSplitting => 10,
        AttackCategory::MaliciousUpload => 11,
        AttackCategory::Xxe => 12,
        AttackCategory::BusinessRuleViolation => 13,
        AttackCategory::LdapInjection => 13,
        AttackCategory::Deserialization => 13,
        AttackCategory::XpathInjection => 13,
        AttackCategory::Ssrf => 14,
        AttackCategory::CommandInjection => 15,
        AttackCategory::PathTraversal => 16,
        AttackCategory::Xss => 17,
        AttackCategory::SqlInjection => 18,
        _ => 19,
    }
}

impl SatguardianSatEngine {
    pub fn new() -> Self {
        Self::with_config(IslandsConfig::default(), BusinessRulesConfig::default())
    }

    pub fn with_config(
        islands_config: IslandsConfig,
        business_rules_config: BusinessRulesConfig,
    ) -> Self {
        let mut islands = HashMap::new();
        islands.insert(
            "ISLAND-SQLI".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-SQLI".to_string(),
                name: "SQL Grammar & AST Island".to_string(),
                category: AttackCategory::SqlInjection,
                description: "Deterministic island covering AST tautologies, unmapped UNION projections, stacked queries, and time delays.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{SQLi}} \equiv \neg (Token(\text{QUOTE}) \land (Token(\text{TAUTOLOGY}) \lor Token(\text{UNION\_SELECT}) \lor Token(\text{STACKED\_DDL}) \lor Token(\text{TIME\_DELAY})))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-XSS".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-XSS".to_string(),
                name: "DOM Context & Execution Island".to_string(),
                category: AttackCategory::Xss,
                description: "Deterministic island covering executable HTML contexts, event attributes, and scripting URIs.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{XSS}} \equiv \neg (Token(\text{TAG\_OPEN}) \land (Token(\text{SCRIPT\_CONTEXT}) \lor Token(\text{EVENT\_TRIGGER}) \lor Token(\text{JS\_SCHEME})))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-RCE".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-RCE".to_string(),
                name: "OS Shell & Dynamic Runtime Island".to_string(),
                category: AttackCategory::CommandInjection,
                description: "Deterministic island covering shell metacharacter cascades, subshell substitutions, and dynamic code evaluation sinks.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{RCE}} \equiv \neg (Token(\text{SHELL\_METACHAR}) \land Token(\text{SYS\_EXEC}) \lor Token(\text{DYNAMIC\_EVAL\_SINK}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-LFI".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-LFI".to_string(),
                name: "Filesystem Sandbox Boundary Island".to_string(),
                category: AttackCategory::PathTraversal,
                description: "Deterministic island covering relative path escapes and direct access to protected kernel/system descriptors.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{LFI}} \equiv \neg (Token(\text{TRAVERSAL\_DOTS}) \lor Token(\text{SENSITIVE\_SYSTEM\_PATH}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-SSRF".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-SSRF".to_string(),
                name: "Network Perimeter & Cloud Metadata Island".to_string(),
                category: AttackCategory::Ssrf,
                description: "Deterministic island covering cloud metadata endpoints (169.254.169.254), loopback interfaces, and private protocols.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{SSRF}} \equiv \neg (Token(\text{PROXY\_URI}) \land (Token(\text{METADATA\_ENDPOINT}) \lor Token(\text{LOOPBACK\_TARGET})))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-GRAPHQL".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-GRAPHQL".to_string(),
                name: "GraphQL Grammar & AST Invariant Island".to_string(),
                category: AttackCategory::GraphqlAbuse,
                description: "Deterministic island protecting GraphQL services against introspection probes, cyclic recursive nesting exhaustion, and alias multiplexing.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{GraphQL}} \equiv \neg (Token(\text{INTROSPECTION}) \lor Token(\text{DEEP\_NESTING}) \lor Token(\text{BATCHING}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-JSON-PROTO".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-JSON-PROTO".to_string(),
                name: "Strict JSON Schema & Prototype Sandbox Island".to_string(),
                category: AttackCategory::PrototypePollution,
                description: "Deterministic island preventing JavaScript prototype tampering, object property pollution, and recursive JSON parsing bombs.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Proto}} \equiv \neg (Token(\text{PROTO\_POLLUTION}) \lor Token(\text{SCHEMA\_EXHAUSTION}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-GRPC".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-GRPC".to_string(),
                name: "gRPC & Protobuf Wire Protocol Framing Island".to_string(),
                category: AttackCategory::GrpcSmuggling,
                description: "Deterministic island validating HTTP/2 gRPC 5-byte framing, preventing client status trailer injection and protocol smuggling.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{gRPC}} \equiv \neg (Token(\text{STATUS\_INJECTION}) \lor Token(\text{FRAME\_DESYNC}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-JWT".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-JWT".to_string(),
                name: "Cryptographic Identity & JWT Integrity Island".to_string(),
                category: AttackCategory::JwtTampering,
                description: "Deterministic island enforcing cryptographically signed tokens, preventing alg: none confusion, missing signatures, and header parameter injections.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{JWT}} \equiv \neg (Token(\text{ALG\_NONE}) \lor Token(\text{MISSING\_SIGNATURE}) \lor Token(\text{HEADER\_INJECTION}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-STATEFUL".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-STATEFUL".to_string(),
                name: "Temporal Sliding Window & Behavioral Dynamics Island".to_string(),
                category: AttackCategory::RateLimitDdos,
                description: "Deterministic island monitoring temporal event frequencies across sliding atomic ring counters to block L7 bursts, distributed brute-force, and credential stuffing.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Stateful}} \equiv \neg (Token(\text{RATE\_LIMIT\_BURST}) \lor Token(\text{CREDENTIAL\_STUFFING}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-WORDPRESS".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-WORDPRESS".to_string(),
                name: "WordPress Shield & Reconnaissance Defense Island".to_string(),
                category: AttackCategory::CmsWordpressProbe,
                description: "Deterministic island protecting non-WordPress web applications against automated scanner probes (/wp-admin, /wp-login, xmlrpc.php, plugins enumeration).".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{WP}} \equiv \neg (Token(\text{WORDPRESS\_PROBE}) \land \text{IslandsConfig.wordpress\_shield})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-EXPOSURE".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-EXPOSURE".to_string(),
                name: "Sensitive Files & Backdoor Exposure Defense Island".to_string(),
                category: AttackCategory::SensitiveExposureProbe,
                description: "Deterministic island preventing unauthorized access to sensitive configuration dumps (.env, .git, .aws/credentials, phpMyAdmin, actuator, backup.sql).".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Exp}} \equiv \neg (Token(\text{SENSITIVE\_EXPOSURE}) \land \text{IslandsConfig.exposure\_shield})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-FRAMEWORK".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-FRAMEWORK".to_string(),
                name: "Framework Remote Code Execution & JNDI Defense Island".to_string(),
                category: AttackCategory::FrameworkExploitProbe,
                description: "Deterministic island neutralizing known framework vulnerabilities including Log4j JNDI injection, Spring Expression Language, and Laravel Ignition RCE.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Framework}} \equiv \neg (Token(\text{FRAMEWORK\_EXPLOIT}) \land \text{IslandsConfig.framework\_shield})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-NOSQL".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-NOSQL".to_string(),
                name: "NoSQL Operator Injection Island".to_string(),
                category: AttackCategory::NoSqlInjection,
                description: "Deterministic island covering MongoDB-style operator injection via JSON keys ($ne, $gt, $regex, $where) and bracket query parameters.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{NoSQL}} \equiv \neg (Token(\text{NOSQL\_OPERATOR}) \land \text{JSON\_OR\_QUERY\_CONTEXT})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-SSTI".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-SSTI".to_string(),
                name: "Server-Side Template Injection Island".to_string(),
                category: AttackCategory::Ssti,
                description: "Deterministic island covering template engine expressions (Jinja {{ }}, FreeMarker ${ }, Velocity #set) that reach reflection or runtime sinks.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{SSTI}} \equiv \neg (Token(\text{TEMPLATE\_DELIMITER}) \land Token(\text{ENGINE\_SINK}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-HEADER-INJECTION".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-HEADER-INJECTION".to_string(),
                name: "HTTP Header Integrity Island".to_string(),
                category: AttackCategory::HttpResponseSplitting,
                description: "Deterministic island covering CRLF response splitting and Host/Forwarded header manipulation used in password-reset and cache-poisoning attacks.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Header}} \equiv \neg (Token(\text{CRLF\_RESPONSE\_HDR}) \lor Token(\text{HOST\_HEADER\_ANOMALY}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-UPLOAD".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-UPLOAD".to_string(),
                name: "Malicious File Upload Island".to_string(),
                category: AttackCategory::MaliciousUpload,
                description: "Deterministic island covering uploads with executable/server-parsed extensions and server-side script tags in upload contexts.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Upload}} \equiv \neg (Token(\text{EXECUTABLE\_FILENAME}) \lor (Token(\text{SERVER\_SIDE\_TAG}) \land Token(\text{UPLOAD\_CTX})))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-XML-ENTITY".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-XML-ENTITY".to_string(),
                name: "XML External Entity Island".to_string(),
                category: AttackCategory::Xxe,
                description: "Deterministic island covering XML documents declaring external or parameter entities that reach SYSTEM/PUBLIC identifiers (XXE, OOB exfiltration).".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{XXE}} \equiv \neg (Token(\text{DOCTYPE}) \land Token(\text{ENTITY}_{\text{SYSTEM}/\text{PUBLIC}}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-LDAP-INJECTION".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-LDAP-INJECTION".to_string(),
                name: "LDAP Filter Injection Island".to_string(),
                category: AttackCategory::LdapInjection,
                description: "Deterministic island covering LDAP filter metacharacters ( *)(, )(|, (=*) coupled with directory attribute context in authentication or search parameters.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{LDAP}} \equiv \neg (Token(\text{LDAP\_FILTER\_META}) \land Token(\text{DIRECTORY\_ATTR\_CTX}))".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-DESERIALIZATION".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-DESERIALIZATION".to_string(),
                name: "Insecure Deserialization Island".to_string(),
                category: AttackCategory::Deserialization,
                description: "Deterministic island covering serialized object markers for Java (rO0AB), PHP (O:n:\"Class\"), .NET ViewState (/wEP) and BinaryFormatter (AAEAAAD) payloads.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Deser}} \equiv \neg Token(\text{SERIALIZED\_OBJECT\_MARKER})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-PROTOCOL-SEMANTICS".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-PROTOCOL-SEMANTICS".to_string(),
                name: "Protocol Semantics & Identity Island".to_string(),
                category: AttackCategory::ProtocolSemantics,
                description: "Deterministic island covering HTTP desync framing contradictions, WebDAV verbs on REST endpoints, OAuth redirect_uri abuse, SAML assertion smuggling, cache deception paths, and IDN homograph hosts.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Proto}} \equiv \neg Token(\text{DESYNC} \lor \text{WEBDAV} \lor \text{OAUTH\_ABUSE} \lor \text{SAML} \lor \text{DECEPTION} \lor \text{HOMOGRAPH})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-CONTENT-OBFUSCATION".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-CONTENT-OBFUSCATION".to_string(),
                name: "Content Obfuscation & Forgery Island".to_string(),
                category: AttackCategory::ContentObfuscation,
                description: "Deterministic island covering ANSI escape sequences, forged log lines, nested-quantifier ReDoS payloads, raw SMTP command injection, JSON-RPC dangerous dispatch, and absolute upload paths.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Obf}} \equiv \neg Token(\text{ANSI} \lor \text{LOG\_FORGE} \lor \text{NESTED\_QUANT} \lor \text{SMTP} \lor \text{RPC\_EXEC} \lor \text{ABS\_UPLOAD})".to_string(),
                confidence: 1.0,
            },
        );
        islands.insert(
            "ISLAND-BUSINESS-RULES".to_string(),
            CertaintyIsland {
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                name: "Customer Declarative Business Policies & Access Boundary Island".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                description: "Customer-defined declarative business policies covering method whitelist/blacklist, source IP controls, mandatory security tokens, and payload size thresholds.".to_string(),
                formal_invariant: r"\mathcal{I}_{\text{Biz}} \equiv \bigwedge_{r \in \text{Rules}} \text{Predicate}_r(Req)".to_string(),
                confidence: 1.0,
            },
        );

        let mut rules = HashMap::new();
        // SQL Injection Rules
        rules.insert(
            "SAT-SQLI-01".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-01".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "Tautological Disjunction Invariant".to_string(),
                description: "Detects boolean tautologies (' OR '1'='1', ' OR 1=1) that force query truth value.".to_string(),
                invariant_formula: r"Token(\text{QUOTE}) \land Token(\text{OR}/\text{AND}) \land Expression(\text{IdenticalEquality})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SQLI-02".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-02".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "UNION SELECT AST Branching".to_string(),
                description: "Detects unauthorized schema introspection and second-order exfiltration via UNION projection.".to_string(),
                invariant_formula: r"Token(\text{UNION}) \land Token(\text{SELECT}/\text{ALL}) \land Token(\text{FROM}/\text{NULL})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SQLI-03".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-03".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "Blind Time-Delay Injection Invariant".to_string(),
                description: "Identifies sleep, waitfor, or benchmark primitive calls designed for blind timing exfiltration.".to_string(),
                invariant_formula: r"Token(\text{SLEEP} \lor \text{WAITFOR} \lor \text{BENCHMARK} \lor \text{PG\_SLEEP})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SQLI-04".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-04".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "Stacked Query / Destructive DDL Invariant".to_string(),
                description: "Identifies semicolon query termination combined with destructive DDL statements (DROP, TRUNCATE, ALTER, INSERT, DELETE).".to_string(),
                invariant_formula: r"Token(\text{SEMICOLON}) \land Token(\text{DROP} \lor \text{TRUNCATE} \lor \text{ALTER} \lor \text{INSERT} \lor \text{DELETE})".to_string(),
                confidence: 1.0,
            },
        );

        // XSS Rules
        rules.insert(
            "SAT-XSS-01".to_string(),
            DeductionRule {
                rule_id: "SAT-XSS-01".to_string(),
                island_id: "ISLAND-XSS".to_string(),
                category: AttackCategory::Xss,
                name: "Direct DOM Script Execution Invariant".to_string(),
                description: "Identifies executable <script> context injected into unescaped reflection channels.".to_string(),
                invariant_formula: r"Token(\text{TAG\_OPEN}) \land Token(\text{SCRIPT}) \land Token(\text{ALERT}/\text{SRC}/\text{EVAL}/\text{LOCATION})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-XSS-02".to_string(),
            DeductionRule {
                rule_id: "SAT-XSS-02".to_string(),
                island_id: "ISLAND-XSS".to_string(),
                category: AttackCategory::Xss,
                name: "HTML Event Handler Vector".to_string(),
                description: "Detects JavaScript event triggers inside non-script HTML tags (e.g., onerror, onload, onmouseover, svg/onload).".to_string(),
                invariant_formula: r"Token(\text{EVENT\_ATTR}: \text{on\w+}) \land Token(\text{ASSIGN}) \land Token(\text{JS\_CALL})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-XSS-03".to_string(),
            DeductionRule {
                rule_id: "SAT-XSS-03".to_string(),
                island_id: "ISLAND-XSS".to_string(),
                category: AttackCategory::Xss,
                name: "Pseudo-Protocol & SVG Injection".to_string(),
                description:
                    "Detects javascript: pseudo-protocol or embedded vector SVG execution contexts."
                        .to_string(),
                invariant_formula:
                    r"Token(\text{JAVASCRIPT\_URI} \lor (\text{SVG\_TAG} \land \text{ONLOAD}))"
                        .to_string(),
                confidence: 1.0,
            },
        );

        // RCE Rules
        rules.insert(
            "SAT-RCE-01".to_string(),
            DeductionRule {
                rule_id: "SAT-RCE-01".to_string(),
                island_id: "ISLAND-RCE".to_string(),
                category: AttackCategory::CommandInjection,
                name: "Shell Metacharacter Pipe/Cascade Invariant".to_string(),
                description: "Detects command chaining operators (| , && , ; , $(...)) followed by binary execution.".to_string(),
                invariant_formula: r"Token(\text{SHELL\_OP}: [|;\&\$\`]) \land Token(\text{EXEC\_BINARY}: [\text{cat,bash,curl,wget,nc,powershell,sh,whoami,id}])".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-RCE-02".to_string(),
            DeductionRule {
                rule_id: "SAT-RCE-02".to_string(),
                island_id: "ISLAND-RCE".to_string(),
                category: AttackCategory::CommandInjection,
                name: "Subshell Command Expansion".to_string(),
                description: "Detects evaluation backticks or subshell expansions $(...) targeting runtime shells.".to_string(),
                invariant_formula: r"Token(\text{SUBSHELL\_OPEN}) \land Token(\text{SYS\_CALL}) \land Token(\text{SUBSHELL\_CLOSE})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-RCE-03".to_string(),
            DeductionRule {
                rule_id: "SAT-RCE-03".to_string(),
                island_id: "ISLAND-RCE".to_string(),
                category: AttackCategory::CommandInjection,
                name: "Dynamic Code Runtime Evaluation Sink".to_string(),
                description: "Detects dynamic evaluation sinks in Python, Node, PHP (os.system, subprocess, eval(), exec(), runtime.exec, passthru).".to_string(),
                invariant_formula: r"Token(\text{RUNTIME\_IMPORT} \lor \text{SINK}) \land Token(\text{OS\_SYSTEM} \lor \text{EVAL} \lor \text{EXEC} \lor \text{SUBPROCESS})".to_string(),
                confidence: 1.0,
            },
        );

        // Path Traversal Rules
        rules.insert(
            "SAT-PATH-01".to_string(),
            DeductionRule {
                rule_id: "SAT-PATH-01".to_string(),
                island_id: "ISLAND-LFI".to_string(),
                category: AttackCategory::PathTraversal,
                name: "Directory Traversal Invariant".to_string(),
                description: "Detects parent directory sequence traversal combined with critical system file access.".to_string(),
                invariant_formula: r"Token(\text{DOT\_DOT\_SLASH})^+ \land Token(\text{SYSTEM\_TARGET}: [\text{etc/passwd, win.ini, boot.ini}])".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-PATH-02".to_string(),
            DeductionRule {
                rule_id: "SAT-PATH-02".to_string(),
                island_id: "ISLAND-LFI".to_string(),
                category: AttackCategory::PathTraversal,
                name: "Direct Sensitive System Path Disclosure".to_string(),
                description: "Detects direct targeting of /proc/self, /etc/passwd, /etc/shadow or Windows system roots.".to_string(),
                invariant_formula: r"Token(\text{DIRECT\_FS\_TARGET}: [\text{/proc/self/}, \text{/etc/passwd}, \text{/etc/shadow}, \text{win.ini}])".to_string(),
                confidence: 1.0,
            },
        );

        // SSRF Rules
        rules.insert(
            "SAT-SSRF-01".to_string(),
            DeductionRule {
                rule_id: "SAT-SSRF-01".to_string(),
                island_id: "ISLAND-SSRF".to_string(),
                category: AttackCategory::Ssrf,
                name: "Internal Cloud Metadata & RFC1918 Exfiltration".to_string(),
                description: "Detects redirection or proxying to 169.254.169.254, localhost, or private IP spaces.".to_string(),
                invariant_formula: r"Token(\text{URI\_PARAM}) \land Token(\text{PRIVATE\_IP} \lor \text{METADATA\_ADDR} \lor \text{GOPHER\_SCHEME})".to_string(),
                confidence: 1.0,
            },
        );

        // GraphQL Rules
        rules.insert(
            "SAT-GQL-01".to_string(),
            DeductionRule {
                rule_id: "SAT-GQL-01".to_string(),
                island_id: "ISLAND-GRAPHQL".to_string(),
                category: AttackCategory::GraphqlAbuse,
                name: "GraphQL Schema Introspection Probe".to_string(),
                description: "Detects schema dumping or reconnaissance via __schema, __type, or __directive introspection in production.".to_string(),
                invariant_formula: r"Token(\text{GRAPHQL\_INTROSPECTION\_PROBE})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-GQL-02".to_string(),
            DeductionRule {
                rule_id: "SAT-GQL-02".to_string(),
                island_id: "ISLAND-GRAPHQL".to_string(),
                category: AttackCategory::GraphqlAbuse,
                name: "GraphQL Cyclic AST Deep Nesting DoS".to_string(),
                description: "Detects cyclic recursion or recursive field nesting exceeding safe AST depth limits (> 6 levels).".to_string(),
                invariant_formula: r"Expression(\text{AST\_Depth} > 6) \implies \text{VIOLATION}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-GQL-03".to_string(),
            DeductionRule {
                rule_id: "SAT-GQL-03".to_string(),
                island_id: "ISLAND-GRAPHQL".to_string(),
                category: AttackCategory::GraphqlAbuse,
                name: "GraphQL Batch / Alias Multiplication Amplification".to_string(),
                description: "Detects batch query overloading via JSON arrays or multiple alias definitions designed to evade rate limits.".to_string(),
                invariant_formula: r"Token(\text{GRAPHQL\_BATCH\_ARRAY} \lor \text{ALIAS\_AMPLIFICATION})".to_string(),
                confidence: 1.0,
            },
        );

        rules.insert(
            "SAT-GQL-04".to_string(),
            DeductionRule {
                rule_id: "SAT-GQL-04".to_string(),
                island_id: "ISLAND-GRAPHQL".to_string(),
                category: AttackCategory::GraphqlAbuse,
                name: "GraphQL Abuse Probe (Recon / Destructive Mutation / Secret Projection)".to_string(),
                description: "Detects bare __typename recon, destructive mutation operations, or credential fields projected in a GraphQL selection set.".to_string(),
                invariant_formula: r"Token(\text{GRAPHQL\_ABUSE\_PROBE})".to_string(),
                confidence: 1.0,
            },
        );

        // JSON & Prototype Rules
        rules.insert(
            "SAT-JSON-01".to_string(),
            DeductionRule {
                rule_id: "SAT-JSON-01".to_string(),
                island_id: "ISLAND-JSON-PROTO".to_string(),
                category: AttackCategory::PrototypePollution,
                name: "Object Prototype Property Pollution Invariant".to_string(),
                description: "Detects malicious property injection into JavaScript object prototypes (__proto__, constructor.prototype).".to_string(),
                invariant_formula: r"Token(\text{__proto__} \lor \text{constructor.prototype} \lor \text{__defineGetter__})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-JSON-02".to_string(),
            DeductionRule {
                rule_id: "SAT-JSON-02".to_string(),
                island_id: "ISLAND-JSON-PROTO".to_string(),
                category: AttackCategory::PrototypePollution,
                name: "JSON Recursive Nesting Schema Exhaustion".to_string(),
                description: "Detects recursive JSON schema nesting depth exceeding parser memory boundaries (> 20 levels).".to_string(),
                invariant_formula: r"Expression(\text{JSON\_Depth} > 20) \implies \text{VIOLATION}".to_string(),
                confidence: 1.0,
            },
        );

        // gRPC Rules
        rules.insert(
            "SAT-GRPC-01".to_string(),
            DeductionRule {
                rule_id: "SAT-GRPC-01".to_string(),
                island_id: "ISLAND-GRPC".to_string(),
                category: AttackCategory::GrpcSmuggling,
                name: "Client-Injected gRPC Status Trailer Smuggling".to_string(),
                description: "Detects unauthorized client injection of grpc-status or grpc-message in request headers to forge upstream authorization responses.".to_string(),
                invariant_formula: r"Token(\text{CLIENT\_GRPC\_STATUS\_HEADER})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-GRPC-02".to_string(),
            DeductionRule {
                rule_id: "SAT-GRPC-02".to_string(),
                island_id: "ISLAND-GRPC".to_string(),
                category: AttackCategory::GrpcSmuggling,
                name: "gRPC Wire Protocol Framing Anomaly".to_string(),
                description: "Detects invalid compression flags, truncated frame headers, or stream length desynchronization in gRPC messages.".to_string(),
                invariant_formula: r"Token(\text{GRPC\_FRAMING\_DESYNC})".to_string(),
                confidence: 1.0,
            },
        );

        // JWT Rules
        rules.insert(
            "SAT-JWT-01".to_string(),
            DeductionRule {
                rule_id: "SAT-JWT-01".to_string(),
                island_id: "ISLAND-JWT".to_string(),
                category: AttackCategory::JwtTampering,
                name: "JWT Algorithm Confusion & Unsigned Token Invariant".to_string(),
                description: "Detects tokens with alg: none or tokens missing the cryptographic signature component entirely.".to_string(),
                invariant_formula: r"Token(\text{JWT\_ALG\_NONE} \lor \text{JWT\_MISSING\_SIG})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-JWT-02".to_string(),
            DeductionRule {
                rule_id: "SAT-JWT-02".to_string(),
                island_id: "ISLAND-JWT".to_string(),
                category: AttackCategory::JwtTampering,
                name: "JWT Header Parameter Injection (JKU/JWK/KID Spoofing)".to_string(),
                description: "Detects attacker-controlled public keys in jwk/jku or directory traversal/SQLi in kid parameter.".to_string(),
                invariant_formula: r"Token(\text{JWT\_INJECTED\_JWK} \lor \text{KID\_TRAVERSAL} \lor \text{JKU\_SSRF})".to_string(),
                confidence: 1.0,
            },
        );

        // Stateful Behavioral Rules
        rules.insert(
            "SAT-STATE-01".to_string(),
            DeductionRule {
                rule_id: "SAT-STATE-01".to_string(),
                island_id: "ISLAND-STATEFUL".to_string(),
                category: AttackCategory::RateLimitDdos,
                name: "Layer-7 Request Rate Limit Exceeded (DDoS Ring Counter)".to_string(),
                description: "Detects volumetric Layer-7 request bursts exceeding temporal sliding window invariant on atomic ring counter.".to_string(),
                invariant_formula: r"Expression(\text{SlidingWindowCount} > \text{GlobalThreshold})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-STATE-02".to_string(),
            DeductionRule {
                rule_id: "SAT-STATE-02".to_string(),
                island_id: "ISLAND-STATEFUL".to_string(),
                category: AttackCategory::CredentialStuffing,
                name: "Distributed Credential Stuffing & Auth Flooding Invariant".to_string(),
                description: "Detects brute force or distributed credential stuffing attempts targeting sensitive authentication endpoints.".to_string(),
                invariant_formula: r"Expression(\text{AuthWindowCount} > \text{AuthThreshold})".to_string(),
                confidence: 1.0,
            },
        );

        // WordPress Shield Rules
        rules.insert(
            "SAT-WP-01".to_string(),
            DeductionRule {
                rule_id: "SAT-WP-01".to_string(),
                island_id: "ISLAND-WORDPRESS".to_string(),
                category: AttackCategory::CmsWordpressProbe,
                name: "WordPress Administrative & Login Endpoint Reconnaissance".to_string(),
                description: "Detects unauthorized discovery probes targeting /wp-admin, /wp-login.php, or xmlrpc.php on non-WordPress applications.".to_string(),
                invariant_formula: r"Token(\text{WORDPRESS\_ADMIN\_OR\_LOGIN}) \land \text{wordpress\_shield}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-WP-02".to_string(),
            DeductionRule {
                rule_id: "SAT-WP-02".to_string(),
                island_id: "ISLAND-WORDPRESS".to_string(),
                category: AttackCategory::CmsWordpressProbe,
                name: "WordPress Component & User Enumeration Probing".to_string(),
                description: "Detects automated scanning of wp-content/plugins, wp-includes, or wp-json user enumeration.".to_string(),
                invariant_formula: r"Token(\text{WORDPRESS\_ENUMERATION}) \land \text{wordpress\_shield}".to_string(),
                confidence: 1.0,
            },
        );

        // Sensitive File Exposure Rules
        rules.insert(
            "SAT-EXP-01".to_string(),
            DeductionRule {
                rule_id: "SAT-EXP-01".to_string(),
                island_id: "ISLAND-EXPOSURE".to_string(),
                category: AttackCategory::SensitiveExposureProbe,
                name: "Configuration & Secret Credential Disclosure Probe".to_string(),
                description: "Detects unauthorized discovery probes targeting .env files, .git repositories, or cloud credentials.".to_string(),
                invariant_formula: r"Token(\text{DOT\_ENV\_OR\_GIT\_SECRET}) \land \text{exposure\_shield}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-EXP-02".to_string(),
            DeductionRule {
                rule_id: "SAT-EXP-02".to_string(),
                island_id: "ISLAND-EXPOSURE".to_string(),
                category: AttackCategory::SensitiveExposureProbe,
                name: "Database & Server Management Console Probing".to_string(),
                description: "Detects unauthenticated exposure scanning of phpMyAdmin, adminer, or actuator consoles.".to_string(),
                invariant_formula: r"Token(\text{DATABASE\_MGMT\_CONSOLE}) \land \text{exposure\_shield}".to_string(),
                confidence: 1.0,
            },
        );

        // Framework Exploit Rules
        rules.insert(
            "SAT-FW-01".to_string(),
            DeductionRule {
                rule_id: "SAT-FW-01".to_string(),
                island_id: "ISLAND-FRAMEWORK".to_string(),
                category: AttackCategory::FrameworkExploitProbe,
                name: "Log4j JNDI Remote Code Execution Injection".to_string(),
                description: "Detects ${jndi:ldap/rmi/dns...} remote lookup injection patterns in URI, headers, or body.".to_string(),
                invariant_formula: r"Token(\text{JNDI\_LOOKUP\_EXPRESSION}) \land \text{framework\_shield}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-FW-02".to_string(),
            DeductionRule {
                rule_id: "SAT-FW-02".to_string(),
                island_id: "ISLAND-FRAMEWORK".to_string(),
                category: AttackCategory::FrameworkExploitProbe,
                name: "Spring/Framework Expression Language Injection".to_string(),
                description: "Detects SpEL or Laravel ignition evaluation vectors targeting web application backends.".to_string(),
                invariant_formula: r"Token(\text{FRAMEWORK\_EXPRESSION\_EVAL}) \land \text{framework\_shield}".to_string(),
                confidence: 1.0,
            },
        );

        rules.insert(
            "SAT-SQLI-05".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-05".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "Error-Based / Blind SQLi Function Invariant".to_string(),
                description: "Detects error-based extraction (extractvalue, updatexml), blind timing (waitfor delay) and file-write primitives (into outfile, load_file) inside an injection context.".to_string(),
                invariant_formula: r"Token(\text{SQLI\_FUNC}: \text{extractvalue}/\text{updatexml}/\text{waitfor}/\text{outfile}) \land \text{InjectionContext}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-XML-01".to_string(),
            DeductionRule {
                rule_id: "SAT-XML-01".to_string(),
                island_id: "ISLAND-XML-ENTITY".to_string(),
                category: AttackCategory::Xxe,
                name: "XXE External Entity Invariant".to_string(),
                description: "Detects DOCTYPE/ENTITY declarations resolving SYSTEM or PUBLIC identifiers, enabling file read and out-of-band exfiltration.".to_string(),
                invariant_formula: r"Token(\text{ENTITY}_{\text{SYSTEM}/\text{PUBLIC}}) \land Token(\text{DOCTYPE}\text{\_BLOCK})".to_string(),
                confidence: 1.0,
            },
        );

        // NoSQL / SSTI / Header / Upload coverage rules
        rules.insert(
            "SAT-NOSQL-01".to_string(),
            DeductionRule {
                rule_id: "SAT-NOSQL-01".to_string(),
                island_id: "ISLAND-NOSQL".to_string(),
                category: AttackCategory::NoSqlInjection,
                name: "NoSQL Operator Injection Invariant".to_string(),
                description: "Detects MongoDB-style query operators ($ne, $gt, $regex, $where) smuggled as JSON keys or bracket parameters to bypass authentication and filters.".to_string(),
                invariant_formula: r"Token(\text{NOSQL\_OPERATOR}: \text{\$ne}/\text{\$gt}/\text{\$regex}/\text{\$where}) \land \text{JSON\_or\_bracket\_context}".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SSTI-01".to_string(),
            DeductionRule {
                rule_id: "SAT-SSTI-01".to_string(),
                island_id: "ISLAND-SSTI".to_string(),
                category: AttackCategory::Ssti,
                name: "Server-Side Template Expression Invariant".to_string(),
                description: "Detects template engine delimiters (Jinja {{ }}, FreeMarker ${ }, Velocity #set) coupled with reflection or runtime sinks.".to_string(),
                invariant_formula: r"Token(\text{TEMPLATE\_DELIMITER}) \land Token(\text{ENGINE\_SINK}: \_self/\?new/\$class/forName)".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-HDR-01".to_string(),
            DeductionRule {
                rule_id: "SAT-HDR-01".to_string(),
                island_id: "ISLAND-HEADER-INJECTION".to_string(),
                category: AttackCategory::HttpResponseSplitting,
                name: "CRLF Response Header Injection Invariant".to_string(),
                description: "Detects decoded CRLF sequences introducing forged response headers (Set-Cookie, Location, X-*) into redirects or reflections.".to_string(),
                invariant_formula: r"Token(\text{CRLF}) \land Token(\text{RESPONSE\_HEADER\_NAME})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-HDR-02".to_string(),
            DeductionRule {
                rule_id: "SAT-HDR-02".to_string(),
                island_id: "ISLAND-HEADER-INJECTION".to_string(),
                category: AttackCategory::HostHeaderInjection,
                name: "Host / Forwarded Header Manipulation Invariant".to_string(),
                description: "Detects IP literals in the Host header or forwarding headers (X-Forwarded-Host, Forwarded) that disagree with it.".to_string(),
                invariant_formula: r"Token(\text{HOST}=\text{IP\_LITERAL}) \lor Token(\text{XFH} \neq \text{HOST})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-UP-01".to_string(),
            DeductionRule {
                rule_id: "SAT-UP-01".to_string(),
                island_id: "ISLAND-UPLOAD".to_string(),
                category: AttackCategory::MaliciousUpload,
                name: "Malicious Upload Payload Invariant".to_string(),
                description: "Detects uploads carrying executable/server-parsed extensions (.php, .phtml, .htaccess) or server-side script tags in upload context.".to_string(),
                invariant_formula: r"Token(\text{EXECUTABLE\_FILENAME}) \lor (Token(\text{SERVER\_SIDE\_TAG}) \land Token(\text{UPLOAD\_CTX}))".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SQLI-06".to_string(),
            DeductionRule {
                rule_id: "SAT-SQLI-06".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::SqlInjection,
                name: "Quote-Free SQLi Subquery / Blind Tautology Invariant".to_string(),
                description: "Detects subquery injection (=(SELECT ... FROM ...)), CASE WHEN conditional expressions and HAVING tautologies that carry no quote or UNION keyword.".to_string(),
                invariant_formula: r"Token(\text{SQLI\_SUBQUERY}: \text{SELECT..FROM\_in\_expr}) \lor Token(\text{SQLI\_CASE\_HAVING})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-RCE-04".to_string(),
            DeductionRule {
                rule_id: "SAT-RCE-04".to_string(),
                island_id: "ISLAND-RCE".to_string(),
                category: AttackCategory::CommandInjection,
                name: "IFS-Substitution Command Invocation Invariant".to_string(),
                description: "Detects shell command binaries separated by ${IFS}/$IFS whitespace substitution, a filter-evasion form of command injection.".to_string(),
                invariant_formula: r"Token(\text{CMD\_BINARY}) \land Token(\text{IFS\_SEPARATOR})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SSTI-02".to_string(),
            DeductionRule {
                rule_id: "SAT-SSTI-02".to_string(),
                island_id: "ISLAND-SSTI".to_string(),
                category: AttackCategory::Ssti,
                name: "SSTI Arithmetic / Embedded Tag Invariant".to_string(),
                description: "Detects template arithmetic probes ({{7*7}}, ${7*7}, <%=7*7%>) and embedded executable tags (<%= system() %>, <% Runtime %>) used to confirm or exploit SSTI.".to_string(),
                invariant_formula: r"Token(\text{TEMPLATE\_ARITHMETIC}) \lor Token(\text{EMBEDDED\_EXEC\_TAG})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SSRF-02".to_string(),
            DeductionRule {
                rule_id: "SAT-SSRF-02".to_string(),
                island_id: "ISLAND-SSRF".to_string(),
                category: AttackCategory::Ssrf,
                name: "SSRF Userinfo / Scheme-Relative Invariant".to_string(),
                description: "Detects private-network targets smuggled via URL userinfo (http://evil@127.0.0.1/) or scheme-relative //host syntax inside URL parameters.".to_string(),
                invariant_formula: r"Token(\text{URL\_USERINFO}) \land Token(\text{PRIVATE\_TARGET}) \lor Token(\text{SCHEME\_RELATIVE}) \land Token(\text{URL\_PARAM})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-LDAP-01".to_string(),
            DeductionRule {
                rule_id: "SAT-LDAP-01".to_string(),
                island_id: "ISLAND-LDAP-INJECTION".to_string(),
                category: AttackCategory::LdapInjection,
                name: "LDAP Filter Metacharacter Invariant".to_string(),
                description: "Detects LDAP filter injection sequences ( *)(, )(|, (=*)) coupled with directory attribute names (uid, cn, objectClass, userPassword) in auth or search parameters.".to_string(),
                invariant_formula: r"Token(\text{LDAP\_FILTER\_META}) \land Token(\text{DIRECTORY\_ATTR\_CTX})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-DESER-01".to_string(),
            DeductionRule {
                rule_id: "SAT-DESER-01".to_string(),
                island_id: "ISLAND-DESERIALIZATION".to_string(),
                category: AttackCategory::Deserialization,
                name: "Serialized Object Marker Invariant".to_string(),
                description: "Detects serialized object markers for Java (rO0AB), PHP (O:n:\"Class\"), .NET ViewState (/wEP) and BinaryFormatter (AAEAAAD) enabling remote code execution via gadget chains.".to_string(),
                invariant_formula: r"Token(\text{SERIALIZED\_OBJECT\_MARKER}: \text{JAVA}/\text{PHP}/\text{DOTNET})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-XPATH-01".to_string(),
            DeductionRule {
                rule_id: "SAT-XPATH-01".to_string(),
                island_id: "ISLAND-SQLI".to_string(),
                category: AttackCategory::XpathInjection,
                name: "XPath Expression Injection Invariant".to_string(),
                description: "Detects XPath location paths (//a/b, //*, (//expr) coupled with quote/boolean context or XPath function names (substring, contains, name, position).".to_string(),
                invariant_formula: r"Token(\text{XPATH\_LOCATION\_EXPR}) \land Token(\text{QUOTE/BOOLEAN\_CTX})".to_string(),
                confidence: 1.0,
            },
        );

        // Customer Business Rules
        rules.insert(
            "SAT-BIZ-01".to_string(),
            DeductionRule {
                rule_id: "SAT-BIZ-01".to_string(),
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                name: "Customer Business HTTP Method Restriction Violation".to_string(),
                description: "Request method violates customer-defined allowed/blocked HTTP verb specification for this route.".to_string(),
                invariant_formula: r"Expression(\text{Method} \notin \text{AllowedMethods})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-BIZ-02".to_string(),
            DeductionRule {
                rule_id: "SAT-BIZ-02".to_string(),
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                name: "Customer Business Source IP Access Control Violation".to_string(),
                description: "Client IP address violates customer-defined IP whitelist or is explicitly blacklisted.".to_string(),
                invariant_formula: r"Expression(\text{ClientIP} \notin \text{AllowedIPs} \lor \text{ClientIP} \in \text{BlockedIPs})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-BIZ-03".to_string(),
            DeductionRule {
                rule_id: "SAT-BIZ-03".to_string(),
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                name: "Customer Business Mandatory Security Header Missing".to_string(),
                description: "Request lacks customer-defined mandatory authorization or tenant identifier headers.".to_string(),
                invariant_formula: r"Expression(\text{RequiredHeader} \notin \text{Headers})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-BIZ-04".to_string(),
            DeductionRule {
                rule_id: "SAT-BIZ-04".to_string(),
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                name: "Customer Business Payload Size Boundary Violation".to_string(),
                description: "Request payload size exceeds customer-defined maximum byte threshold for this endpoint.".to_string(),
                invariant_formula: r"Expression(\text{BodySize} > \text{MaxBodyBytes})".to_string(),
                confidence: 1.0,
            },
        );

        rules.insert(
            "SAT-SEM-01".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-01".to_string(),
                island_id: "ISLAND-PROTOCOL-SEMANTICS".to_string(),
                category: AttackCategory::ProtocolSemantics,
                name: "HTTP Desync / WebDAV / Cache Deception Invariant".to_string(),
                description: "Framing-header contradictions (CL+TE, malformed/duplicated lengths), non-REST WebDAV verbs, account paths served as static assets, unkeyed cache-poisoning inputs, param-level absolute-path traversal, or CMS plugin-probe actions.".to_string(),
                invariant_formula: r"Token(\text{DESYNC} \lor \text{WEBDAV} \lor \text{DECEPTION})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SEM-02".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-02".to_string(),
                island_id: "ISLAND-PROTOCOL-SEMANTICS".to_string(),
                category: AttackCategory::ProtocolSemantics,
                name: "Identity Protocol Abuse Invariant".to_string(),
                description: "OAuth redirect_uri userinfo/protocol-relative/scheme abuse or flow anomalies (missing state, redirect_uri on token endpoint), SAML assertion messages, or IDN homograph/punycode hosts.".to_string(),
                invariant_formula: r"Token(\text{OAUTH\_ABUSE} \lor \text{SAML} \lor \text{HOMOGRAPH})".to_string(),
                confidence: 1.0,
            },
        );
        rules.insert(
            "SAT-SEM-03".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-03".to_string(),
                island_id: "ISLAND-BUSINESS-RULES".to_string(),
                category: AttackCategory::BusinessRuleViolation,
                name: "Privileged Field / Numeric Anomaly / CSV Formula Invariant".to_string(),
                description: "Mass-assignment privileged keys with grant values, impossible numeric fields (negative qty/price, discount>100), cross-parameter numeric anomalies (benefit >> ceiling), or spreadsheet formula cells.".to_string(),
                invariant_formula: r"Token(\text{PRIVILEGED\_FIELD} \lor \text{NUMERIC\_ANOMALY} \lor \text{CSV\_FORMULA})".to_string(),
                confidence: 0.9,
            },
        );
        rules.insert(
            "SAT-SEM-04".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-04".to_string(),
                island_id: "ISLAND-CONTENT-OBFUSCATION".to_string(),
                category: AttackCategory::ContentObfuscation,
                name: "ANSI Escape / Log Forgery / Nested Quantifier Invariant".to_string(),
                description: "Terminal escape sequences, forged timestamped log lines, nested-quantifier regex shapes, invisible/bidi characters, homoglyph keyword smuggling, or mixed-script evasion tokens in parameters.".to_string(),
                invariant_formula: r"Token(\text{ANSI} \lor \text{LOG\_FORGE} \lor \text{NESTED\_QUANT})".to_string(),
                confidence: 0.95,
            },
        );
        rules.insert(
            "SAT-SEM-05".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-05".to_string(),
                island_id: "ISLAND-CONTENT-OBFUSCATION".to_string(),
                category: AttackCategory::CommandInjection,
                name: "SMTP / RPC Dispatch / Absolute Upload Path Invariant".to_string(),
                description: "Raw SMTP verbs at line start, JSON-RPC dispatch to exec/shell primitives, or filename= pointing at absolute server paths.".to_string(),
                invariant_formula: r"Token(\text{SMTP} \lor \text{RPC\_EXEC} \lor \text{ABS\_UPLOAD})".to_string(),
                confidence: 0.95,
            },
        );
        rules.insert(
            "SAT-SEM-06".to_string(),
            DeductionRule {
                rule_id: "SAT-SEM-06".to_string(),
                island_id: "ISLAND-XML-ENTITY".to_string(),
                category: AttackCategory::Xxe,
                name: "XSLT / XQuery Expression Invariant".to_string(),
                description: "Server-side stylesheet or query language expressions (xsl:, doc(), collection(), declare variable) reaching file/network sinks.".to_string(),
                invariant_formula: r"Token(\text{XSLT} \lor \text{XQUERY})".to_string(),
                confidence: 0.9,
            },
        );
        rules.insert(
            "SAT-XSS-04".to_string(),
            DeductionRule {
                rule_id: "SAT-XSS-04".to_string(),
                island_id: "ISLAND-XSS".to_string(),
                category: AttackCategory::Xss,
                name: "Diagram DSL Injection Invariant".to_string(),
                description: "Mermaid %%{init:...}%% directives or diagram click/href javascript: bindings smuggling script execution or markup through the renderer.".to_string(),
                invariant_formula: r"Token(\text{MERMAID\_INIT} \lor \text{DIAGRAM\_SCRIPT\_BIND})".to_string(),
                confidence: 0.9,
            },
        );

        // Pre-warm AST regex singletons so first evaluation is instant
        let _ = AstLexer::tokenize("");

        Self {
            islands,
            rules,
            dynamic_clauses: RwLock::new(Vec::new()),
            islands_config: RwLock::new(islands_config),
            business_rules_config: RwLock::new(business_rules_config),
        }
    }

    /// Dynamically updates protection islands and customer business rules in memory.
    pub fn update_config(&self, islands: IslandsConfig, biz: BusinessRulesConfig) {
        *self.islands_config.write().unwrap() = islands;
        *self.business_rules_config.write().unwrap() = biz;
    }

    /// Injects or updates a customer declarative business policy in hot memory.
    pub fn add_customer_business_rule(&self, rule: CustomBusinessRule) {
        let mut w = self.business_rules_config.write().unwrap();
        w.enabled = true;
        w.rules.retain(|r| r.id != rule.id);
        w.rules.push(rule);
    }

    /// Removes a customer declarative business policy by ID.
    pub fn remove_customer_business_rule(&self, rule_id: &str) -> bool {
        let mut w = self.business_rules_config.write().unwrap();
        let initial_len = w.rules.len();
        w.rules.retain(|r| r.id != rule_id);
        w.rules.len() < initial_len
    }

    /// Returns all current active customer business policies.
    pub fn get_customer_business_rules(&self) -> Vec<CustomBusinessRule> {
        self.business_rules_config.read().unwrap().rules.clone()
    }

    /// Hot-compiles a newly simplified rule into the active Fast-Path in-memory table.
    /// Returns false when the clause is a duplicate or the safety cap is reached.
    pub fn register_dynamic_clause(&self, clause: DynamicCompiledClause) -> bool {
        const MAX_DYNAMIC_CLAUSES: usize = 4096;

        let mut w = self.dynamic_clauses.write().unwrap();
        if w.iter().any(|existing| {
            existing.required_mask == clause.required_mask
                && existing.expected_bits == clause.expected_bits
        }) {
            return false;
        }
        if w.len() >= MAX_DYNAMIC_CLAUSES {
            tracing::warn!(
                target: "satguardian::engine",
                "Dynamic clause cap ({}) reached; ignoring clause {}",
                MAX_DYNAMIC_CLAUSES,
                clause.clause_id
            );
            return false;
        }
        w.push(clause);
        true
    }

    pub fn get_rules(&self) -> Vec<DeductionRule> {
        self.rules.values().cloned().collect()
    }

    pub fn get_islands(&self) -> Vec<CertaintyIsland> {
        self.islands.values().cloned().collect()
    }

    pub fn dynamic_clauses_count(&self) -> usize {
        self.dynamic_clauses.read().unwrap().len()
    }

    /// Evaluates an HTTP request payload against all Certainty Islands and dynamic rules.
    /// In-memory latency on the pinned corpus measures p50 ~20 µs; it excludes TLS, the proxy
    /// hop and the upstream, so it is not an end-to-end request time.
    pub fn evaluate_payload(&self, req: &HttpRequestPayload) -> ProofChain {
        self.evaluate_payload_with_verdict(req, None)
    }

    /// Evaluates an HTTP request payload against all Certainty Islands, dynamic rules, and stateful verdicts.
    pub fn evaluate_payload_with_verdict(
        &self,
        req: &HttpRequestPayload,
        stateful: Option<&StatefulVerdict>,
    ) -> ProofChain {
        let t_start = Instant::now();

        // Bound the work one request can cause: an oversized payload is refused before lexing.
        const MAX_SAFE_DEPTH: usize = 1_048_576; // 1 MB boundary
        if req.query_string.len() > MAX_SAFE_DEPTH || req.body.len() > MAX_SAFE_DEPTH {
            let elapsed = t_start.elapsed();
            return ProofChain {
                request_id: req.id.clone(),
                is_violation: true,
                category: AttackCategory::BusinessRuleViolation,
                action: AttackDecision::Block,
                execution_path: ExecutionPath::FastPathLocal,
                matched_rules: Vec::new(),
                active_islands: vec!["ISLAND-BUSINESS-RULES".to_string()],
                active_tokens: vec!["PAYLOAD_EXCEEDS_MAX_SAFE_DEPTH".to_string()],
                deduction_steps: vec![
                    "[EARLY-EXIT] Payload length exceeded the 1 MB safety threshold.".to_string(),
                ],
                decision_reason: r"\text{Length}(req) > 1\text{MB} \implies \mathbf{BLOCK}"
                    .to_string(),
                rule_match_details:
                    "PayloadSize <= MAX_SAFE_DEPTH breached => ACTION_BLOCK [EARLY_EXIT]"
                        .to_string(),
                execution_time_us: (elapsed.as_secs_f64() * 1_000_000.0 * 100.0).round() / 100.0,
            };
        }

        let mut tokens: LexicalTokens = AstLexer::tokenize_request(req);
        if let Some(sv) = stateful {
            if sv.is_rate_limit {
                tokens.has_stateful_rate_limit = true;
                tokens
                    .active_token_names
                    .push("STATEFUL_BURST_RATE_LIMIT_EXCEEDED".to_string());
            }
            if sv.is_credential_stuffing {
                tokens.has_stateful_credential_stuffing = true;
                tokens
                    .active_token_names
                    .push("STATEFUL_CREDENTIAL_STUFFING_BURST".to_string());
            }
        }

        let fv: FeatureVector = FeatureBinarizer::binarize(req, &tokens);

        let mut matched_rules: Vec<DeductionRule> = Vec::with_capacity(4);
        let mut active_islands: Vec<String> = Vec::with_capacity(4);
        let mut deduction_steps: Vec<String> = Vec::with_capacity(4);
        let mut active_tokens: Vec<String> = tokens.active_token_names.clone();

        // 1. ISLAND-SQLI evaluation
        if tokens.has_tautology {
            if let Some(r) = self.rules.get("SAT-SQLI-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] AST Tokenizer resolved boolean tautological predicate evaluating to TRUE constant.".to_string());
            }
        }
        if tokens.has_union_select {
            if let Some(r) = self.rules.get("SAT-SQLI-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] Grammar parser detected unmapped UNION SELECT tree projection overriding primary cardinality.".to_string());
            }
        }
        if tokens.has_time_delay {
            if let Some(r) = self.rules.get("SAT-SQLI-03") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] AST detected asynchronous time delay primitive invocation (SLEEP/BENCHMARK).".to_string());
            }
        }
        if tokens.has_stacked_ddl {
            if let Some(r) = self.rules.get("SAT-SQLI-04") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] Stacked query delimiter followed by destructive DDL modification detected.".to_string());
            }
        }

        // 2. ISLAND-XSS evaluation
        if tokens.has_script_tag || tokens.has_xss_extended_signal {
            if let Some(r) = self.rules.get("SAT-XSS-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XSS".to_string());
                deduction_steps.push("[ISLAND-XSS] HTML lexer extracted unauthorized executable SCRIPT context in untrusted stream.".to_string());
            }
        }
        if tokens.has_event_handler || tokens.has_svg_onload {
            if let Some(r) = self.rules.get("SAT-XSS-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XSS".to_string());
                deduction_steps.push("[ISLAND-XSS] Lexical analysis extracted event handler attribute violating strict CSP syntax tree.".to_string());
            }
        }
        if tokens.has_js_scheme {
            if let Some(r) = self.rules.get("SAT-XSS-03") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XSS".to_string());
                deduction_steps.push(
                    "[ISLAND-XSS] Detected executable JavaScript pseudo-protocol URI scheme."
                        .to_string(),
                );
            }
        }
        if tokens.has_mermaid_injection {
            if let Some(r) = self.rules.get("SAT-XSS-04") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XSS".to_string());
                deduction_steps.push(
                    "[ISLAND-XSS] Mermaid init directive or diagram script binding reaches the renderer."
                        .to_string(),
                );
            }
        }

        // 3. ISLAND-RCE evaluation
        if tokens.has_shell_chain || tokens.has_rce_extended_signal {
            if let Some(r) = self.rules.get("SAT-RCE-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-RCE".to_string());
                deduction_steps.push("[ISLAND-RCE] POSIX/PowerShell shell chaining metacharacter operator coupled with executable binary detected.".to_string());
            }
        }
        if tokens.has_subshell {
            if let Some(r) = self.rules.get("SAT-RCE-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-RCE".to_string());
                deduction_steps.push("[ISLAND-RCE] Dynamic command substitution subshell context `$()` or backtick sequence detected.".to_string());
            }
        }
        if tokens.has_dynamic_eval
            || tokens.has_php_injection_signal
            || tokens.has_nodejs_injection_signal
            || tokens.has_java_runtime_sink
        {
            if let Some(r) = self.rules.get("SAT-RCE-03") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-RCE".to_string());
                deduction_steps.push("[ISLAND-RCE] Dynamic code evaluation sink (os.system / subprocess / eval / exec) identified.".to_string());
            }
        }

        // 4. ISLAND-LFI evaluation
        if tokens.has_path_traversal || tokens.has_lfi_extended_signal {
            if let Some(r) = self.rules.get("SAT-PATH-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-LFI".to_string());
                deduction_steps.push("[ISLAND-LFI] Relative path resolution breached sandbox boundaries pointing to system roots.".to_string());
            }
        }
        if tokens.has_sensitive_system_path {
            if let Some(r) = self.rules.get("SAT-PATH-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-LFI".to_string());
                deduction_steps.push("[ISLAND-LFI] Direct targeting of sensitive kernel process memory (/proc/self) or system credentials detected.".to_string());
            }
        }

        // 5. ISLAND-SSRF evaluation
        if tokens.has_ssrf_metadata {
            if let Some(r) = self.rules.get("SAT-SSRF-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SSRF".to_string());
                deduction_steps.push("[ISLAND-SSRF] Internal cloud metadata service address (169.254.169.254) or RFC1918 loopback targeted via proxy argument.".to_string());
            }
        }

        // 6. ISLAND-GRAPHQL evaluation
        if tokens.has_graphql_introspection {
            if let Some(r) = self.rules.get("SAT-GQL-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRAPHQL".to_string());
                deduction_steps.push("[ISLAND-GRAPHQL] GraphQL schema introspection query probe (__schema/__type) rejected by AST policy.".to_string());
            }
        }
        if tokens.has_graphql_deep_nesting {
            if let Some(r) = self.rules.get("SAT-GQL-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRAPHQL".to_string());
                deduction_steps.push("[ISLAND-GRAPHQL] Deep cyclic AST recursion exceeds safe schema depth boundary (> 6 levels).".to_string());
            }
        }
        if tokens.has_graphql_batching {
            if let Some(r) = self.rules.get("SAT-GQL-03") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRAPHQL".to_string());
                deduction_steps.push("[ISLAND-GRAPHQL] GraphQL batch array or alias multiplexing amplification detected.".to_string());
            }
        }
        if tokens.has_graphql_abuse {
            if let Some(r) = self.rules.get("SAT-GQL-04") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRAPHQL".to_string());
                deduction_steps.push("[ISLAND-GRAPHQL] GraphQL abuse probe: bare __typename recon, destructive mutation, or secret-field projection.".to_string());
            }
        }

        // 7. ISLAND-JSON-PROTO evaluation
        if tokens.has_proto_pollution {
            if let Some(r) = self.rules.get("SAT-JSON-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-JSON-PROTO".to_string());
                deduction_steps.push("[ISLAND-JSON-PROTO] Malicious prototype pollution property assignment (__proto__ / constructor.prototype).".to_string());
            }
        }
        if tokens.has_json_deep_nesting {
            if let Some(r) = self.rules.get("SAT-JSON-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-JSON-PROTO".to_string());
                deduction_steps.push("[ISLAND-JSON-PROTO] Recursive JSON schema nesting bomb exceeds parser stack bounds (> 20 levels).".to_string());
            }
        }

        // 8. ISLAND-GRPC evaluation
        if tokens.has_grpc_status_injection {
            if let Some(r) = self.rules.get("SAT-GRPC-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRPC".to_string());
                deduction_steps.push("[ISLAND-GRPC] Client request header contains server trailer injection (grpc-status / grpc-message).".to_string());
            }
        }
        if tokens.has_grpc_smuggling {
            if let Some(r) = self.rules.get("SAT-GRPC-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-GRPC".to_string());
                deduction_steps.push("[ISLAND-GRPC] gRPC framing protocol violation or wire stream length desynchronization.".to_string());
            }
        }

        // 9. ISLAND-JWT evaluation
        if tokens.has_jwt_alg_none || tokens.has_jwt_missing_sig {
            if let Some(r) = self.rules.get("SAT-JWT-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-JWT".to_string());
                deduction_steps.push("[ISLAND-JWT] Insecure JWT with alg: 'none' or missing cryptographic signature.".to_string());
            }
        }
        if tokens.has_jwt_header_injection {
            if let Some(r) = self.rules.get("SAT-JWT-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-JWT".to_string());
                deduction_steps.push("[ISLAND-JWT] Malicious JWT header parameter injection (untrusted JKU/JWK or directory traversal/SQLi in kid).".to_string());
            }
        }

        // 10. ISLAND-STATEFUL evaluation
        if tokens.has_stateful_rate_limit {
            if let Some(r) = self.rules.get("SAT-STATE-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-STATEFUL".to_string());
                deduction_steps.push("[ISLAND-STATEFUL] Atomic ring counter temporal sliding window exceeded Layer-7 burst limit.".to_string());
            }
        }
        if tokens.has_stateful_credential_stuffing {
            if let Some(r) = self.rules.get("SAT-STATE-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-STATEFUL".to_string());
                deduction_steps.push("[ISLAND-STATEFUL] High-frequency authentication attempt burst on sensitive endpoint (Credential Stuffing).".to_string());
            }
        }

        // 11. ISLAND-WORDPRESS evaluation
        let islands_cfg = self.islands_config.read().unwrap().clone();
        let full_inspectable = req.full_inspectable_string();
        if islands_cfg.wordpress_shield && tokens.has_wordpress_probe {
            if full_inspectable.contains("wp-admin")
                || full_inspectable.contains("wp-login.php")
                || full_inspectable.contains("xmlrpc.php")
            {
                if let Some(r) = self.rules.get("SAT-WP-01") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-WORDPRESS".to_string());
                    deduction_steps.push("[ISLAND-WORDPRESS] WordPress administrative or authentication endpoint probe blocked by active shield.".to_string());
                }
            } else {
                if let Some(r) = self.rules.get("SAT-WP-02") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-WORDPRESS".to_string());
                    deduction_steps.push("[ISLAND-WORDPRESS] WordPress plugin, theme, or user enumeration scan detected.".to_string());
                }
            }
        }

        // 12. ISLAND-EXPOSURE evaluation
        if islands_cfg.exposure_shield && tokens.has_sensitive_file_probe {
            if full_inspectable.contains(".env")
                || full_inspectable.contains(".git")
                || full_inspectable.contains("id_rsa")
                || full_inspectable.contains(".aws")
            {
                if let Some(r) = self.rules.get("SAT-EXP-01") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-EXPOSURE".to_string());
                    deduction_steps.push("[ISLAND-EXPOSURE] Probing for environment files (.env), version control (.git), or cloud credentials.".to_string());
                }
            } else {
                if let Some(r) = self.rules.get("SAT-EXP-02") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-EXPOSURE".to_string());
                    deduction_steps.push("[ISLAND-EXPOSURE] Probing for unauthenticated database administration console (phpMyAdmin, Adminer, Actuator).".to_string());
                }
            }
        }

        // 13. ISLAND-FRAMEWORK evaluation
        if islands_cfg.framework_shield && tokens.has_framework_exploit_probe {
            if full_inspectable.contains("jndi:") {
                if let Some(r) = self.rules.get("SAT-FW-01") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-FRAMEWORK".to_string());
                    deduction_steps.push("[ISLAND-FRAMEWORK] Remote JNDI code execution injection (Log4j vector) detected.".to_string());
                }
            } else {
                if let Some(r) = self.rules.get("SAT-FW-02") {
                    matched_rules.push(r.clone());
                    active_islands.push("ISLAND-FRAMEWORK".to_string());
                    deduction_steps.push("[ISLAND-FRAMEWORK] Framework expression language / remote execution probe detected.".to_string());
                }
            }
        }

        // 14. ISLAND-BUSINESS-RULES evaluation
        let biz_cfg = self.business_rules_config.read().unwrap().clone();
        if biz_cfg.enabled {
            let client_ip_str = req.client_ip.as_deref().unwrap_or("");
            for rule in biz_cfg.rules.iter().filter(|r| r.enabled) {
                // Check path match
                if let Some(ref prefix) = rule.path_prefix {
                    if !prefix.is_empty() && !req.path.starts_with(prefix) {
                        continue;
                    }
                }
                let prefix_str = rule.path_prefix.as_deref().unwrap_or("*");

                // Check blocked methods
                if let Some(ref blocked) = rule.blocked_methods {
                    if blocked.iter().any(|m| m.eq_ignore_ascii_case(&req.method)) {
                        if let Some(r) = self.rules.get("SAT-BIZ-01") {
                            let mut customized = r.clone();
                            customized.description = format!(
                                "Method '{}' is blocked on route '{}' by rule '{}'",
                                req.method, prefix_str, rule.name
                            );
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!("[ISLAND-BUSINESS-RULES] Method '{}' explicitly prohibited by rule '{}'.", req.method, rule.name));
                        }
                        break;
                    }
                }

                // Check allowed methods (if specified)
                if let Some(ref allowed) = rule.allowed_methods {
                    if !allowed.is_empty()
                        && !allowed.iter().any(|m| m.eq_ignore_ascii_case(&req.method))
                    {
                        if let Some(r) = self.rules.get("SAT-BIZ-01") {
                            let mut customized = r.clone();
                            customized.description = format!(
                                "Method '{}' is not in allowed list {:?} for route '{}'",
                                req.method, allowed, prefix_str
                            );
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!(
                                "[ISLAND-BUSINESS-RULES] Method '{}' not allowed by rule '{}'.",
                                req.method, rule.name
                            ));
                        }
                        break;
                    }
                }

                // Check blocked IPs
                if let Some(ref blocked_ips) = rule.blocked_ips {
                    if !client_ip_str.is_empty() && blocked_ips.iter().any(|ip| ip == client_ip_str)
                    {
                        if let Some(r) = self.rules.get("SAT-BIZ-02") {
                            let mut customized = r.clone();
                            customized.description = format!(
                                "Client IP '{}' is blacklisted by rule '{}'",
                                client_ip_str, rule.name
                            );
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!("[ISLAND-BUSINESS-RULES] Client IP '{}' matched blacklist in rule '{}'.", client_ip_str, rule.name));
                        }
                        break;
                    }
                }

                // Check allowed IPs (if specified, acts as whitelist)
                if let Some(ref allowed_ips) = rule.allowed_ips {
                    if !client_ip_str.is_empty()
                        && !allowed_ips.is_empty()
                        && !allowed_ips.iter().any(|ip| ip == client_ip_str)
                    {
                        if let Some(r) = self.rules.get("SAT-BIZ-02") {
                            let mut customized = r.clone();
                            customized.description = format!(
                                "Client IP '{}' not in allowed whitelist {:?} for rule '{}'",
                                client_ip_str, allowed_ips, rule.name
                            );
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!("[ISLAND-BUSINESS-RULES] Client IP '{}' denied by whitelist in rule '{}'.", client_ip_str, rule.name));
                        }
                        break;
                    }
                }

                // Check required headers
                if let Some(ref req_headers) = rule.required_headers {
                    let missing_header = req_headers
                        .iter()
                        .find(|h| !req.headers.keys().any(|k| k.eq_ignore_ascii_case(h)));
                    if let Some(missing) = missing_header {
                        if let Some(r) = self.rules.get("SAT-BIZ-03") {
                            let mut customized = r.clone();
                            customized.description = format!(
                                "Mandatory header '{}' missing for route '{}' under rule '{}'",
                                missing, prefix_str, rule.name
                            );
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!("[ISLAND-BUSINESS-RULES] Missing required header '{}' specified by rule '{}'.", missing, rule.name));
                        }
                        break;
                    }
                }

                // Check max body bytes
                if let Some(max_bytes) = rule.max_body_bytes {
                    if req.body.len() > max_bytes {
                        if let Some(r) = self.rules.get("SAT-BIZ-04") {
                            let mut customized = r.clone();
                            customized.description = format!("Request body size ({} bytes) exceeds limit of {} bytes defined in rule '{}'", req.body.len(), max_bytes, rule.name);
                            matched_rules.push(customized);
                            active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                            deduction_steps.push(format!("[ISLAND-BUSINESS-RULES] Body length {} exceeds {} limit for rule '{}'.", req.body.len(), max_bytes, rule.name));
                        }
                        break;
                    }
                }
            }
        }

        // 14a-bis. ISLAND-SQLI extended coverage (error-based / blind functions)
        if tokens.has_sqli_danger_func || tokens.has_sqli_extended_signal {
            if let Some(r) = self.rules.get("SAT-SQLI-05") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] Error-based/blind SQLi primitive (extractvalue/updatexml/waitfor/outfile) inside injection context.".to_string());
            }
        }

        // 14b. ISLAND-NOSQL evaluation
        if tokens.has_nosql_operator {
            if let Some(r) = self.rules.get("SAT-NOSQL-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-NOSQL".to_string());
                deduction_steps.push("[ISLAND-NOSQL] NoSQL operator key ($ne/$gt/$regex/$where) detected in JSON document or bracket query parameter.".to_string());
            }
        }

        // 14c. ISLAND-SSTI evaluation
        if tokens.has_ssti_expression {
            if let Some(r) = self.rules.get("SAT-SSTI-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SSTI".to_string());
                deduction_steps.push("[ISLAND-SSTI] Template engine delimiters coupled with reflection/runtime sink detected (Jinja/FreeMarker/Velocity).".to_string());
            }
        }

        // 14d. ISLAND-HEADER-INJECTION evaluation
        if tokens.has_crlf_header_injection {
            if let Some(r) = self.rules.get("SAT-HDR-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-HEADER-INJECTION".to_string());
                deduction_steps.push("[ISLAND-HEADER-INJECTION] Decoded CRLF introduces a forged response header (response splitting).".to_string());
            }
        }
        if tokens.has_host_header_anomaly || tokens.has_method_override_abuse {
            if let Some(r) = self.rules.get("SAT-HDR-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-HEADER-INJECTION".to_string());
                deduction_steps.push("[ISLAND-HEADER-INJECTION] Host header carries an IP literal, forwarding header disagrees with it, or method-override header smuggles a privileged verb.".to_string());
            }
        }

        // 14e. ISLAND-UPLOAD evaluation
        if tokens.has_malicious_upload {
            if let Some(r) = self.rules.get("SAT-UP-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-UPLOAD".to_string());
                deduction_steps.push("[ISLAND-UPLOAD] Upload payload carries executable extension or server-side script tag in upload context.".to_string());
            }
        }

        // 14f. ISLAND-XML-ENTITY evaluation
        if tokens.has_xxe_entity {
            if let Some(r) = self.rules.get("SAT-XML-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XML-ENTITY".to_string());
                deduction_steps.push("[ISLAND-XML-ENTITY] XML DOCTYPE declares external/parameter ENTITY resolving SYSTEM or PUBLIC identifier.".to_string());
            }
        }

        // 14g. ISLAND-SQLI extended coverage (subquery / CASE / HAVING)
        if tokens.has_sqli_subquery || tokens.has_sqli_case_having {
            if let Some(r) = self.rules.get("SAT-SQLI-06") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI] Quote-free SQLi primitive: subquery expression, CASE WHEN conditional or HAVING tautology.".to_string());
            }
        }

        // 14h. ISLAND-RCE extended coverage (${IFS} command invocation)
        if tokens.has_cmd_ifs_binary {
            if let Some(r) = self.rules.get("SAT-RCE-04") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-RCE".to_string());
                deduction_steps.push("[ISLAND-RCE] Shell command binary separated by ${IFS} whitespace substitution.".to_string());
            }
        }

        // 14i. ISLAND-SSTI extended coverage (arithmetic probes / embedded tags)
        if tokens.has_ssti_arith || tokens.has_ssti_embedded {
            if let Some(r) = self.rules.get("SAT-SSTI-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SSTI".to_string());
                deduction_steps.push("[ISLAND-SSTI] Template arithmetic probe or embedded executable tag (<%= system() %>).".to_string());
            }
        }

        // 14j. ISLAND-SSRF extended coverage (userinfo trick / scheme-relative)
        if tokens.has_ssrf_userinfo
            || tokens.has_ssrf_scheme_rel
            || tokens.has_webhook_ssrf_signal
            || tokens.has_rfi_scheme_signal
        {
            if let Some(r) = self.rules.get("SAT-SSRF-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SSRF".to_string());
                deduction_steps.push("[ISLAND-SSRF] Private-network target smuggled via URL userinfo or scheme-relative syntax.".to_string());
            }
        }

        // 14k. ISLAND-LDAP-INJECTION evaluation
        if tokens.has_ldap_injection {
            if let Some(r) = self.rules.get("SAT-LDAP-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-LDAP-INJECTION".to_string());
                deduction_steps.push("[ISLAND-LDAP-INJECTION] LDAP filter metacharacters coupled with directory attribute context.".to_string());
            }
        }

        // 14l. ISLAND-DESERIALIZATION evaluation
        if tokens.has_deserialization || tokens.has_java_deserialization_signal {
            if let Some(r) = self.rules.get("SAT-DESER-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-DESERIALIZATION".to_string());
                deduction_steps.push("[ISLAND-DESERIALIZATION] Serialized object marker detected (Java/PHP/.NET) — gadget-chain RCE vector.".to_string());
            }
        }

        // 14m. ISLAND-SQLI (XPath variant) evaluation
        if tokens.has_xpath_injection {
            if let Some(r) = self.rules.get("SAT-XPATH-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-SQLI".to_string());
                deduction_steps.push("[ISLAND-SQLI/XPATH] XPath location-path expression coupled with quote/boolean context.".to_string());
            }
        }

        // 14n. ISLAND-PROTOCOL-SEMANTICS / CONTENT-OBFUSCATION (v6 layer)
        if tokens.has_smuggling_desync
            || tokens.has_webdav_method
            || tokens.has_cache_deception
            || tokens.has_cache_poisoning_signal
            || tokens.has_path_traversal_signal
            || tokens.has_cms_wordpress_probe_signal
            || tokens.has_parameter_pollution_signal
            || tokens.has_connect_tunnel_signal
            || tokens.has_http2_pseudo_header
            || tokens.has_protocol_injection_signal
            || tokens.has_content_type_confusion_signal
            || tokens.has_websocket_abuse_signal
            || tokens.has_spring4shell_signal
            || tokens.has_open_redirect_signal
            || tokens.has_management_endpoint_signal
            || tokens.has_protocol_enforcement_signal
            || tokens.has_session_token_url_signal
            || tokens.has_client_ip_spoof
            || tokens.has_query_dsl_injection
            || tokens.has_admin_orchestrator_path
        {
            if let Some(r) = self.rules.get("SAT-SEM-01") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-PROTOCOL-SEMANTICS".to_string());
                deduction_steps.push("[ISLAND-PROTOCOL-SEMANTICS] Framing desync, WebDAV verb on REST endpoint, or cache-deception asset path detected.".to_string());
            }
        }
        if tokens.has_oauth_redirect_abuse
            || tokens.has_saml_protocol
            || tokens.has_punycode_host
            || tokens.has_soap_action_abuse
            || tokens.has_oauth_oidc_signal
        {
            if let Some(r) = self.rules.get("SAT-SEM-02") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-PROTOCOL-SEMANTICS".to_string());
                deduction_steps.push("[ISLAND-PROTOCOL-SEMANTICS] OAuth redirect_uri abuse, SAML message, or IDN homograph host detected.".to_string());
            }
        }
        if tokens.has_privileged_field
            || tokens.has_numeric_anomaly
            || tokens.has_csv_formula
            || tokens.has_business_logic_signal
            || tokens.has_type_juggling_signal
            || tokens.has_integer_overflow_signal
        {
            if let Some(r) = self.rules.get("SAT-SEM-03") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-BUSINESS-RULES".to_string());
                deduction_steps.push("[ISLAND-BUSINESS-RULES] Privileged-field assignment, impossible numeric value, or spreadsheet formula cell detected.".to_string());
            }
        }
        if tokens.has_ansi_escape
            || tokens.has_log_forgery
            || tokens.has_nested_quantifier
            || tokens.has_hidden_chars
            || tokens.has_keyword_smuggling
            || tokens.has_unicode_normalization_signal
        {
            if let Some(r) = self.rules.get("SAT-SEM-04") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-CONTENT-OBFUSCATION".to_string());
                deduction_steps.push("[ISLAND-CONTENT-OBFUSCATION] ANSI escape sequence, forged log line, or nested-quantifier ReDoS shape detected.".to_string());
            }
        }
        if tokens.has_smtp_command
            || tokens.has_jsonrpc_exec
            || tokens.has_absolute_upload_path
            || tokens.has_protocol_body_injection
        {
            if let Some(r) = self.rules.get("SAT-SEM-05") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-CONTENT-OBFUSCATION".to_string());
                deduction_steps.push("[ISLAND-CONTENT-OBFUSCATION] Raw SMTP verbs, dangerous RPC dispatch, or absolute upload path detected.".to_string());
            }
        }
        if tokens.has_xslt_stylesheet || tokens.has_xquery_expr {
            if let Some(r) = self.rules.get("SAT-SEM-06") {
                matched_rules.push(r.clone());
                active_islands.push("ISLAND-XML-ENTITY".to_string());
                deduction_steps.push("[ISLAND-XML-ENTITY] XSLT stylesheet or XQuery expression reaching file/network sinks detected.".to_string());
            }
        }

        // 15. Dynamic hot-compiled rules evaluation
        let mut dynamic_matched = false;
        {
            let dyn_rules = self.dynamic_clauses.read().unwrap();
            for clause in dyn_rules.iter() {
                if (fv.bits & clause.required_mask) == clause.expected_bits {
                    dynamic_matched = true;
                    matched_rules.push(DeductionRule {
                        rule_id: clause.clause_id.clone(),
                        island_id: "ISLAND-DYNAMIC-SIMPLIFIED".to_string(),
                        category: clause.category,
                        name: "SATGuardian Cloud Minimized Invariant".to_string(),
                        description: clause.description.clone(),
                        invariant_formula: format!(
                            "Mask({:#x}) == {:#x}",
                            clause.required_mask, clause.expected_bits
                        ),
                        confidence: 1.0,
                    });
                    active_islands.push("ISLAND-DYNAMIC-SIMPLIFIED".to_string());
                    deduction_steps.push(format!(
                        "[HOT-COMPILED] Triggered dynamic exact Boolean clause {}",
                        clause.clause_id
                    ));
                }
            }
        }

        // Deduplicate
        active_islands.sort();
        active_islands.dedup();
        active_tokens.sort();
        active_tokens.dedup();

        let is_violation = !matched_rules.is_empty();
        let category = if is_violation {
            // A payload can match several islands (SpEL is also RCE, `;cat /etc/passwd`
            // is also LFI). Classify by the most specific island, not evaluation order.
            matched_rules
                .iter()
                .map(|r| r.category)
                .min_by_key(|c| category_specificity(*c))
                .unwrap_or(AttackCategory::Unknown)
        } else {
            AttackCategory::Benign
        };
        let action = if is_violation {
            AttackDecision::Block
        } else {
            AttackDecision::Allow
        };

        let exec_path = if dynamic_matched {
            ExecutionPath::HotCompiledDynamic
        } else {
            ExecutionPath::FastPathLocal
        };

        let decision_reason = if is_violation {
            let island_str = active_islands
                .iter()
                .map(|i| format!(r"\mathcal{{I}}_{{\text{{{}}}}}", i.replace("ISLAND-", "")))
                .collect::<Vec<_>>()
                .join(", ");
            let rule_names = matched_rules
                .iter()
                .map(|r| format!(r"\texttt{{{}}}", r.rule_id))
                .collect::<Vec<_>>()
                .join(r" \lor ");
            let safe_tokens = active_tokens
                .iter()
                .map(|t| format!(r"\texttt{{{}}}", t.replace('_', r"\_")))
                .collect::<Vec<_>>()
                .join(", ");
            let safe_cat = category.as_str().to_uppercase().replace('_', r"\_");

            format!(
                r"\begin{{aligned}}
\mathbf{{Certainty\ Island}} &: \{{{island_str}\}} \subset \mathcal{{I}}_{{\text{{SAT}}}} \\[4pt]
\mathbf{{Active\ Tokens}} &: \mathcal{{T}} = \{{{safe_tokens}\}} \\[4pt]
\mathbf{{Invariant\ Rule}} &: \mathcal{{C}}_{{\text{{WAF}}}} \equiv \neg ({rule_names}) \\[4pt]
\mathbf{{SAT\ Evaluation}} &: \text{{Eval}}(\mathcal{{C}}_{{\text{{WAF}}}}, \mathcal{{T}}) \equiv \mathbf{{FALSE}} \implies \mathbf{{BLOCK\ [{safe_cat}]}}
\end{{aligned}}"
            )
        } else {
            deduction_steps.push("[ISLAND-BENIGN] All syntactic AST tokens evaluate to clean grammar bounds; SAT invariant holds.".to_string());
            r"\begin{aligned}
\mathbf{Grammar\ Status} &: \mathcal{T} \subset \mathcal{L}_{\text{Benign}} \\[4pt]
\mathbf{Certainty\ Island} &: \forall \mathcal{I} \in \mathcal{I}_{\text{SAT}}, \; \text{Eval}(\mathcal{I}, \mathcal{T}) = \text{TRUE} \\[4pt]
\mathbf{SAT\ Evaluation} &: \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}) \equiv \mathbf{TRUE} \implies \mathbf{ALLOW\ [BENIGN\ TRAFFIC]}
\end{aligned}".to_string()
        };

        let rule_match_details = if is_violation {
            let rule_ids = matched_rules
                .iter()
                .map(|r| r.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(" | ");
            let tok_ids = active_tokens.join(" AND ");
            format!("({tok_ids}) violates [{rule_ids}] -> ACTION_BLOCK [{category}]")
        } else {
            "No invariant contradiction detected in AST lattice -> ACTION_ALLOW".to_string()
        };

        let elapsed = t_start.elapsed();
        let execution_time_us = elapsed.as_secs_f64() * 1_000_000.0;

        ProofChain {
            request_id: req.id.clone(),
            is_violation,
            category,
            action,
            execution_path: exec_path,
            matched_rules,
            active_islands,
            active_tokens,
            deduction_steps,
            decision_reason,
            rule_match_details,
            execution_time_us: (execution_time_us * 100.0).round() / 100.0,
        }
    }
}
