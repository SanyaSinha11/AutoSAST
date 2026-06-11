"""
Guided Question Templates for Semgrep Security Rules.

These templates provide issue-specific questions that force the LLM to reason
step-by-step about whether a finding is a true or false positive.

The key insight from VulnHalla is that generic prompts lead to poor results.
Issue-specific guided questions dramatically improve accuracy.
"""

from typing import Optional

# Default questions for any security finding
DEFAULT_QUESTIONS = [
    "What is the source of the potentially tainted data in this code?",
    "Is there any sanitization, validation, or encoding applied to the data before it reaches the sink?",
    "What is the sink (dangerous function/operation) that the data flows into?",
    "Are there any security controls in the surrounding context that would prevent exploitation?",
    "Could an attacker realistically control the input that reaches this code path?",
]

# SQL Injection questions
SQL_INJECTION_QUESTIONS = [
    "Is the SQL query constructed using string concatenation or formatting with user input?",
    "Are parameterized queries or prepared statements used instead of string interpolation?",
    "Is there any input validation or sanitization before the data is used in the query?",
    "Does the ORM or database library provide automatic escaping for this operation?",
    "Is the input coming from a trusted source (e.g., internal config) or untrusted source (e.g., user input)?",
    "Are there any allowlist checks that restrict the input to known-safe values?",
    "CRITICAL: Check ALL callers of this method - do ALL callers pass string LITERALS (hardcoded strings) or do some pass user-controlled variables?",
    "Is the query parameter defined as a 'private static final String' constant? If so, it's likely FALSE POSITIVE.",
]

# XSS (Cross-Site Scripting) questions
XSS_QUESTIONS = [
    "Is the user input being rendered directly in HTML without encoding?",
    "Does the framework automatically escape output in this context (e.g., React, Angular)?",
    "Is there explicit HTML encoding/escaping applied before rendering?",
    "What is the output context (HTML body, attribute, JavaScript, CSS, URL)?",
    "Is Content-Security-Policy (CSP) configured to mitigate XSS impact?",
    "Is the input sanitized using a library like DOMPurify or bleach?",
    "CRITICAL: Is the output actually rendered in HTML, or is it used in a non-HTML context (e.g., enum lookup, integer parsing, logging)? Non-HTML contexts are NOT XSS.",
    "Is the value transformed to a safe type (e.g., Integer.parseInt, Enum.valueOf) before output?",
]

# Command Injection questions
COMMAND_INJECTION_QUESTIONS = [
    "Is user input being passed directly to a shell command or system call?",
    "Are shell metacharacters being escaped or filtered?",
    "Is the command constructed using a safe API (e.g., subprocess with list args)?",
    "Is there an allowlist of permitted commands or arguments?",
    "Could an attacker inject shell operators like ;, |, &&, ||, or backticks?",
    "Is the input validated against a strict pattern before use?",
]

# Path Traversal questions
PATH_TRAVERSAL_QUESTIONS = [
    "Is user input used to construct a file path?",
    "Is the path normalized and validated to prevent directory traversal (..)?",
    "Is there a check that the resolved path is within an allowed directory?",
    "Are symbolic links followed, and could they be exploited?",
    "Is the input validated against an allowlist of permitted files/directories?",
    "Does the application run with minimal file system permissions?",
    "CRITICAL: Is the file path from a 'private static final String' constant or hardcoded value? Constants are NOT user-controlled and are FALSE POSITIVE.",
    "Check ALL callers - is the path parameter ALWAYS passed as a string literal?",
]

# Hardcoded Secrets questions
HARDCODED_SECRETS_QUESTIONS = [
    "Is this actually a secret (API key, password, token, cryptographic key) or just a KEY NAME (identifier for map/header lookups like 'dealerId', 'userId')? Key names are NOT secrets.",
    "Does the VALUE look like a real secret (long, random, base64, hex) or a simple identifier string (short, human-readable, camelCase)?",
    "Is this a placeholder, example, or test value rather than a real secret?",
    "Is the value loaded from environment variables or a secrets manager at runtime?",
    "Is this code in a test file where hardcoded values are acceptable?",
    "Does the pattern match common false positives (e.g., variable named 'KEY' but value is just an identifier string)?",
    "CRITICAL: Distinguish between 'String XXX_KEY = \"keyName\"' (key NAME, not a secret) vs 'String SECRET = \"aGVsbG9...\"' (actual secret value).",
    "Is this a TEMPLATE STRING (e.g., 'password=%s') with the actual password coming from a getter (e.g., config.getPassword())? Templates with getters are FALSE POSITIVE.",
    "Does the password/secret come from a method call like .getPassword(), .getSecret(), or config.get()? These are runtime values, NOT hardcoded.",
]

# Insecure Deserialization questions
DESERIALIZATION_QUESTIONS = [
    "Is untrusted data being deserialized using an unsafe method (pickle, yaml.load, etc.)?",
    "Is the data source trusted (internal service) or untrusted (user input)?",
    "Is there signature verification or integrity checking before deserialization?",
    "Is a safe deserialization method available (e.g., yaml.safe_load)?",
    "Are there type restrictions on what can be deserialized?",
]

# SSRF (Server-Side Request Forgery) questions
SSRF_QUESTIONS = [
    "Is user input used to construct a URL for a server-side request?",
    "Is there validation that the URL points to an allowed host/domain?",
    "Are internal/private IP ranges blocked (127.0.0.1, 10.x, 192.168.x, etc.)?",
    "Is URL parsing done safely to prevent bypass techniques?",
    "Is there an allowlist of permitted URLs or domains?",
    "Are redirects followed, and could they be exploited to reach internal resources?",
]

# Cryptography issues questions
CRYPTO_QUESTIONS = [
    "Is a weak or deprecated cryptographic algorithm being used (MD5, SHA1, DES)?",
    "Is the cryptographic operation for security purposes or just checksums/hashing?",
    "Is a secure random number generator used for key/IV generation?",
    "Are cryptographic keys hardcoded or properly managed?",
    "Is the implementation using a well-tested library or custom code?",
]

# GCM Mode specific questions (for IV/nonce reuse detection)
GCM_CRYPTO_QUESTIONS = [
    "How is the IV/nonce generated for each encryption operation? Look for SecureRandom or similar.",
    "Is a NEW IV generated for EACH encryption call, or is the same IV reused?",
    "Is the IV stored/transmitted along with the ciphertext for decryption?",
    "Check the encrypt() method - does it generate a fresh IV before each encryption?",
    "Is there any possibility of IV reuse when encrypting multiple messages with the same key?",
    "What is the IV length being used? (GCM requires 12 bytes/96 bits for optimal security)",
    "Is the key derivation using a proper KDF like PBKDF2 with sufficient iterations?",
]

# AES/Cipher specific questions
CIPHER_QUESTIONS = [
    "What cipher mode is being used (ECB, CBC, GCM, CTR)? ECB is insecure.",
    "For CBC mode, is a random IV used for each encryption?",
    "Is PKCS5/PKCS7 padding used correctly?",
    "Is the encryption key generated securely or hardcoded?",
    "Is the key length sufficient (128, 192, or 256 bits for AES)?",
    "Are there any timing attacks possible in the implementation?",
]

# Authentication/Authorization questions
AUTH_QUESTIONS = [
    "Is authentication being bypassed or weakened in this code?",
    "Are authorization checks present before sensitive operations?",
    "Is the authentication mechanism using secure practices (bcrypt, argon2)?",
    "Are session tokens generated securely and validated properly?",
    "Is there proper handling of authentication failures?",
]

# Java-specific SQL Injection questions
JAVA_SQL_INJECTION_QUESTIONS = [
    "Is the SQL query constructed using string concatenation (+) with user input?",
    "Is PreparedStatement used with parameterized queries (?) instead of Statement?",
    "Are all user inputs passed via setString(), setInt(), or other PreparedStatement setters?",
    "Is there any input validation or sanitization (e.g., allowlist) before SQL construction?",
    "Does the code use an ORM like Hibernate/JPA that provides automatic parameterization?",
    "Is the input coming from HttpServletRequest, @RequestParam, or similar untrusted sources?",
    "Are stored procedures used, and if so, are they parameterized?",
    "CRITICAL: Check the CALLER CHAIN above - is the input sanitized BEFORE it reaches this function (e.g., sanitizeForSql, escapeString, or similar)?",
]

# Java-specific XSS questions
JAVA_XSS_QUESTIONS = [
    "Is user input written directly to HttpServletResponse without encoding?",
    "Does the code use OWASP Java Encoder, StringEscapeUtils, or similar encoding library?",
    "Is the output context HTML body, attribute, JavaScript, or URL?",
    "Does the framework (Spring MVC, JSF, Thymeleaf) auto-escape by default?",
    "Is response.getWriter().write() or out.println() used with user data?",
    "Are Content-Type and X-XSS-Protection headers set correctly?",
]

# Java-specific Command Injection questions
JAVA_COMMAND_INJECTION_QUESTIONS = [
    "Is Runtime.exec() or ProcessBuilder used with user-controlled input?",
    "Is the command constructed as a single string (vulnerable) or String array (safer)?",
    "Are shell metacharacters (;, |, &&, $(), backticks) filtered or escaped?",
    "Is there an allowlist of permitted commands or arguments?",
    "Is user input validated against a strict pattern (regex) before use?",
    "Could the input be used to inject additional arguments or commands?",
]

# Java-specific Path Traversal questions
JAVA_PATH_TRAVERSAL_QUESTIONS = [
    "Is user input used in new File(), Paths.get(), or similar path construction?",
    "Is the path canonicalized using getCanonicalPath() and validated?",
    "Is there a check that the resolved path starts with the expected base directory?",
    "Are path separators (/, \\) and traversal sequences (.., .) filtered?",
    "Is Files.newInputStream() or FileInputStream used with unchecked user paths?",
    "Does the application use a secure file access wrapper or sandbox?",
]

# Java-specific Deserialization questions
JAVA_DESERIALIZATION_QUESTIONS = [
    "Is ObjectInputStream.readObject() used on untrusted data?",
    "Is the data source an HTTP request, socket, or other untrusted input?",
    "Is there a look-ahead ObjectInputStream that validates classes before deserialization?",
    "Are deserialization filters (JEP 290) configured to whitelist allowed classes?",
    "Does the code use a safer serialization format like JSON with type restrictions?",
    "Are gadget chain libraries (Commons Collections, Spring, etc.) in the classpath?",
]

# Java-specific SSRF questions
JAVA_SSRF_QUESTIONS = [
    "Is user input used to construct a URL for HttpURLConnection, HttpClient, or RestTemplate?",
    "Is there validation that the URL points to an allowed host/domain?",
    "Are internal IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x) blocked?",
    "Is URL parsing done safely to prevent bypass via @, #, or redirect techniques?",
    "Does the code follow redirects, and could they be exploited?",
    "Is there DNS rebinding protection or hostname verification?",
]

# Java-specific XXE questions
JAVA_XXE_QUESTIONS = [
    "Is an XML parser (DocumentBuilder, SAXParser, XMLReader) used on untrusted input?",
    "Is setFeature() used to disable external entities and DTDs?",
    "Is XMLConstants.FEATURE_SECURE_PROCESSING enabled?",
    "Are external DTDs, entities, and parameter entities all disabled?",
    "Does the code use a newer, secure-by-default parser configuration?",
    "Is the XML input from an untrusted source like HTTP request or file upload?",
]

# Java-specific Log Injection questions
JAVA_LOG_INJECTION_QUESTIONS = [
    "Is user input logged directly without sanitization?",
    "Are newline characters (\\n, \\r) in the input that could forge log entries?",
    "Is the logging framework (Log4j, Logback) configured to sanitize messages?",
    "Could an attacker inject malicious patterns for log analysis tools?",
    "Is Log4j2 version vulnerable to JNDI injection (CVE-2021-44228)?",
    "Are log messages properly parameterized using {} placeholders?",
]

# Rule ID patterns to question mappings
RULE_PATTERNS = {
    # SQL Injection patterns
    "sql-injection": SQL_INJECTION_QUESTIONS,
    "sqli": SQL_INJECTION_QUESTIONS,
    "tainted-sql": SQL_INJECTION_QUESTIONS,
    
    # XSS patterns
    "xss": XSS_QUESTIONS,
    "cross-site-scripting": XSS_QUESTIONS,
    "reflected-xss": XSS_QUESTIONS,
    "stored-xss": XSS_QUESTIONS,
    "dom-xss": XSS_QUESTIONS,
    
    # Command Injection patterns
    "command-injection": COMMAND_INJECTION_QUESTIONS,
    "os-command": COMMAND_INJECTION_QUESTIONS,
    "shell-injection": COMMAND_INJECTION_QUESTIONS,
    "subprocess": COMMAND_INJECTION_QUESTIONS,
    
    # Path Traversal patterns
    "path-traversal": PATH_TRAVERSAL_QUESTIONS,
    "directory-traversal": PATH_TRAVERSAL_QUESTIONS,
    "lfi": PATH_TRAVERSAL_QUESTIONS,
    
    # Secrets patterns
    "hardcoded-secret": HARDCODED_SECRETS_QUESTIONS,
    "hardcoded-password": HARDCODED_SECRETS_QUESTIONS,
    "hardcoded-credential": HARDCODED_SECRETS_QUESTIONS,
    "secret-in-source": HARDCODED_SECRETS_QUESTIONS,
    "hard_code_key": HARDCODED_SECRETS_QUESTIONS,
    "hard-code-key": HARDCODED_SECRETS_QUESTIONS,
    "hardcoded_key": HARDCODED_SECRETS_QUESTIONS,
    "hardcoded-key": HARDCODED_SECRETS_QUESTIONS,
    
    # Deserialization patterns
    "deserialization": DESERIALIZATION_QUESTIONS,
    "pickle": DESERIALIZATION_QUESTIONS,
    "unsafe-yaml": DESERIALIZATION_QUESTIONS,
    
    # SSRF patterns
    "ssrf": SSRF_QUESTIONS,
    "server-side-request": SSRF_QUESTIONS,
    
    # Crypto patterns
    "weak-crypto": CRYPTO_QUESTIONS,
    "insecure-hash": CRYPTO_QUESTIONS,
    "weak-random": CRYPTO_QUESTIONS,
    "gcm-detection": GCM_CRYPTO_QUESTIONS,
    "gcm": GCM_CRYPTO_QUESTIONS,
    "aes-gcm": GCM_CRYPTO_QUESTIONS,
    "nonce-reuse": GCM_CRYPTO_QUESTIONS,
    "iv-reuse": GCM_CRYPTO_QUESTIONS,
    "cipher": CIPHER_QUESTIONS,
    "encryption": CIPHER_QUESTIONS,
    "aes": CIPHER_QUESTIONS,

    # Auth patterns
    "auth-bypass": AUTH_QUESTIONS,
    "missing-auth": AUTH_QUESTIONS,
    "broken-auth": AUTH_QUESTIONS,

    # Java-specific patterns
    "java.lang.security": JAVA_SQL_INJECTION_QUESTIONS,
    "prepared-statement": JAVA_SQL_INJECTION_QUESTIONS,
    "statement-execute": JAVA_SQL_INJECTION_QUESTIONS,
    "jdbc": JAVA_SQL_INJECTION_QUESTIONS,
    "httpservlet": JAVA_XSS_QUESTIONS,
    "servlet-xss": JAVA_XSS_QUESTIONS,
    "runtime-exec": JAVA_COMMAND_INJECTION_QUESTIONS,
    "processbuilder": JAVA_COMMAND_INJECTION_QUESTIONS,
    "file-path": JAVA_PATH_TRAVERSAL_QUESTIONS,
    "objectinputstream": JAVA_DESERIALIZATION_QUESTIONS,
    "java-deserialization": JAVA_DESERIALIZATION_QUESTIONS,
    "httpurlconnection": JAVA_SSRF_QUESTIONS,
    "url-open": JAVA_SSRF_QUESTIONS,
    "xxe": JAVA_XXE_QUESTIONS,
    "xml-external": JAVA_XXE_QUESTIONS,
    "documentbuilder": JAVA_XXE_QUESTIONS,
    "saxparser": JAVA_XXE_QUESTIONS,
    "log-injection": JAVA_LOG_INJECTION_QUESTIONS,
    "log4j": JAVA_LOG_INJECTION_QUESTIONS,
}

# Java rule prefix patterns for more specific matching
JAVA_RULE_PREFIXES = {
    "java.lang.security.audit.sqli": JAVA_SQL_INJECTION_QUESTIONS,
    "java.lang.security.audit.formatted-sql-string": JAVA_SQL_INJECTION_QUESTIONS,
    "java.lang.security.audit.tainted-sql": JAVA_SQL_INJECTION_QUESTIONS,
    "java.lang.security.audit.xss": JAVA_XSS_QUESTIONS,
    "java.lang.security.audit.command-injection": JAVA_COMMAND_INJECTION_QUESTIONS,
    "java.lang.security.audit.tainted-cmd": JAVA_COMMAND_INJECTION_QUESTIONS,
    "java.lang.security.audit.path-traversal": JAVA_PATH_TRAVERSAL_QUESTIONS,
    "java.lang.security.httpservlet-path-traversal": JAVA_PATH_TRAVERSAL_QUESTIONS,
    "java.lang.security.audit.deserialization": JAVA_DESERIALIZATION_QUESTIONS,
    "java.lang.security.audit.ssrf": JAVA_SSRF_QUESTIONS,
    "java.lang.security.audit.xxe": JAVA_XXE_QUESTIONS,
    "java.lang.security.audit.cbc-padding": CIPHER_QUESTIONS,
    "java.lang.security.audit.crypto.gcm": GCM_CRYPTO_QUESTIONS,
    "java.lang.security.audit.crypto": CIPHER_QUESTIONS,
}


def get_questions_for_rule(rule_id: str, file_path: str = "") -> list[str]:
    """Get guided questions for a specific Semgrep rule ID."""
    rule_lower = rule_id.lower()
    is_java = file_path.endswith(".java")

    # Check Java-specific prefix patterns first for Java files (in order of specificity)
    if is_java:
        # Sort by prefix length (longest first) for more specific matching
        sorted_prefixes = sorted(JAVA_RULE_PREFIXES.items(), key=lambda x: -len(x[0]))
        for prefix, questions in sorted_prefixes:
            if rule_lower.startswith(prefix):
                return questions

    # Check for specific pattern matches in rule ID (order matters - check specific first)
    # Priority patterns for crypto (check these first)
    crypto_priority = ["md5", "sha1", "des-", "weak-hash", "use-of-md5", "des-is-deprecated",
                       "cbc-padding", "gcm", "aes", "cipher", "encryption", "crypto"]
    for pattern in crypto_priority:
        if pattern in rule_lower:
            # Return crypto or cipher questions based on pattern
            if pattern in ["gcm", "nonce-reuse", "iv-reuse"]:
                return GCM_CRYPTO_QUESTIONS
            elif pattern in ["cbc-padding", "aes", "cipher", "encryption"]:
                return CIPHER_QUESTIONS
            else:
                return CRYPTO_QUESTIONS

    # Check for other pattern matches in rule ID
    for pattern, questions in RULE_PATTERNS.items():
        # Skip the broad java.lang.security pattern (handled by prefix matching above)
        if pattern == "java.lang.security":
            continue
        if pattern in rule_lower:
            return questions

    # Return default questions if no specific match
    return DEFAULT_QUESTIONS


def get_questions_for_category(category: str) -> Optional[list[str]]:
    """Get guided questions for a vulnerability category."""
    category_map = {
        "injection": SQL_INJECTION_QUESTIONS,
        "xss": XSS_QUESTIONS,
        "command": COMMAND_INJECTION_QUESTIONS,
        "path": PATH_TRAVERSAL_QUESTIONS,
        "secrets": HARDCODED_SECRETS_QUESTIONS,
        "deserialization": DESERIALIZATION_QUESTIONS,
        "ssrf": SSRF_QUESTIONS,
        "crypto": CRYPTO_QUESTIONS,
        "auth": AUTH_QUESTIONS,
    }
    return category_map.get(category.lower())

