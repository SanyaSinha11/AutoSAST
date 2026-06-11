"""
Sink Verifier - Validates that sinks match vulnerability types.

This module prevents false positives by verifying:
1. XSS findings actually output to HTML/JavaScript
2. SQL injection findings have actual query execution
3. Path traversal findings have user-controlled paths
4. Command injection findings have shell execution

Key insight: Many false positives occur because the "sink" doesn't match
the vulnerability type being flagged.
"""

import re
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities we can verify."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    UNKNOWN = "unknown"


@dataclass
class SinkVerificationResult:
    """Result of sink verification."""
    is_valid_sink: bool
    vulnerability_type: VulnerabilityType
    sink_pattern_matched: Optional[str]
    safe_transform_detected: Optional[str]
    reason: str
    confidence: float
    
    def to_dict(self) -> dict:
        return {
            "is_valid_sink": self.is_valid_sink,
            "vulnerability_type": self.vulnerability_type.value,
            "sink_matched": self.sink_pattern_matched,
            "safe_transform": self.safe_transform_detected,
            "reason": self.reason,
            "confidence": self.confidence,
        }


class SinkVerifier:
    """
    Verifies that the sink type matches the vulnerability being flagged.
    
    This prevents false positives like:
    - XSS flagged when data goes into an enum (not HTML)
    - Path traversal flagged when path is from a constant
    - SQL injection flagged when using parameterized queries
    """
    
    # Sink patterns required for each vulnerability type
    SINK_REQUIREMENTS = {
        VulnerabilityType.XSS: {
            "required_sinks": [
                r"response\.getWriter\s*\(",
                r"\.write\s*\(",
                r"\.print\s*\(",
                r"\.println\s*\(",
                r"out\.print",
                r"innerHTML\s*=",
                r"outerHTML\s*=",
                r"document\.write\s*\(",
                r"\.html\s*\(",                    # jQuery .html()
                r"th:utext\s*=",                   # Thymeleaf unescaped
                r"v-html\s*=",                     # Vue.js
                r"dangerouslySetInnerHTML",        # React
                r"response\.sendRedirect\s*\(",    # Open redirect
                r"HttpServletResponse.*write",
            ],
            "safe_transforms": [
                # Data goes into non-HTML contexts
                r"Enum\.valueOf\s*\(",
                r"Integer\.parseInt\s*\(",
                r"Long\.parseLong\s*\(",
                r"UUID\.fromString\s*\(",
                r"Boolean\.parseBoolean\s*\(",
                r"resolveTekLocale\s*\(",
                r"\.equals\s*\(",
                r"\.matches\s*\(",
                r"Pattern\.compile\s*\(",
                r"logger\.",                        # Logging is not XSS
                r"log\.",
                r"LOG\.",
            ],
        },
        VulnerabilityType.SQL_INJECTION: {
            "required_sinks": [
                r"\.executeQuery\s*\(",
                r"\.execute\s*\(",
                r"\.executeUpdate\s*\(",
                r"createStatement\s*\(\s*\)\.execute",
                r"Statement\s+\w+\s*=",
                r"cursor\.execute\s*\(",
                r"\.rawQuery\s*\(",
                r"jdbcTemplate\.",
            ],
            "safe_transforms": [
                r"PreparedStatement",
                r"\.setString\s*\(",
                r"\.setInt\s*\(",
                r"\.setLong\s*\(",
                r"\.setObject\s*\(",
                r"NamedParameterJdbcTemplate",
                r"@Query\s*\(",  # JPA query
                r"CriteriaBuilder",
                r"entityManager\.createQuery",
            ],
        },
        VulnerabilityType.PATH_TRAVERSAL: {
            "required_sinks": [
                r"new\s+File\s*\(",
                r"new\s+FileInputStream\s*\(",
                r"new\s+FileOutputStream\s*\(",
                r"new\s+FileReader\s*\(",
                r"new\s+FileWriter\s*\(",
                r"Paths\.get\s*\(",
                r"Files\.read",
                r"Files\.write",
                r"Files\.newInputStream",
                r"Files\.newOutputStream",
                r"\.getResourceAsStream\s*\(",
            ],
            "safe_transforms": [
                r"\.getCanonicalPath\s*\(",
                r"\.normalize\s*\(",
                r"\.toRealPath\s*\(",
                r"FilenameUtils\.getName\s*\(",
                r"private\s+static\s+final\s+String",  # Constant path
                r"@Value\s*\(",  # Spring config
            ],
        },
        VulnerabilityType.COMMAND_INJECTION: {
            "required_sinks": [
                r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
                r"ProcessBuilder.*\.start\s*\(",
                r"subprocess\.",
                r"os\.system\s*\(",
                r"os\.popen\s*\(",
                r"\.exec\s*\(",
            ],
            "safe_transforms": [
                r"ProcessBuilder\s*\(\s*\[",  # Array form is safer
                r"shlex\.quote\s*\(",
                r"escapeshellarg\s*\(",
                r"escapeshellcmd\s*\(",
            ],
        },
        VulnerabilityType.HARDCODED_SECRET: {
            "required_sinks": [],  # No sink needed for hardcoded secrets
            "safe_transforms": [
                # Key NAME patterns (not actual secrets)
                r'_KEY\s*=\s*"[a-z]',           # KEY_NAME = "keyName"
                r'_KEY\s*=\s*"[A-Za-z_]+"\s*;', # Simple identifier
                r'private\s+static\s+final\s+String\s+\w+_KEY\s*=',
                r'\.getPassword\s*\(',          # Password from getter
                r'\.getSecret\s*\(',            # Secret from getter
                r'config\.',                    # Config object
                r'properties\.',                # Properties object
                r'System\.getenv\s*\(',         # Environment variable
            ],
            "true_positive_patterns": [
                # Actual hardcoded secrets
                r'password\s*=\s*"[A-Za-z0-9+/=]{20,}"',  # Long encoded string
                r'secret\s*=\s*"[A-Za-z0-9+/=]{20,}"',
                r'api_key\s*=\s*"[A-Za-z0-9]{20,}"',
                r'token\s*=\s*"[A-Za-z0-9._-]{30,}"',
            ],
        },
        VulnerabilityType.SSRF: {
            "required_sinks": [
                r"HttpURLConnection",
                r"URL\s*\(",
                r"\.openConnection\s*\(",
                r"RestTemplate",
                r"WebClient",
                r"HttpClient",
                r"fetch\s*\(",
                r"axios\.",
            ],
            "safe_transforms": [
                r"allowlist",
                r"whitelist",
                r"validateUrl",
                r"\.startsWith\s*\(",
            ],
        },
    }
    
    # Rule ID patterns to vulnerability type mapping
    RULE_TO_VULN_TYPE = {
        "sql": VulnerabilityType.SQL_INJECTION,
        "sqli": VulnerabilityType.SQL_INJECTION,
        "injection": VulnerabilityType.SQL_INJECTION,
        "jdbc": VulnerabilityType.SQL_INJECTION,
        "xss": VulnerabilityType.XSS,
        "cross-site": VulnerabilityType.XSS,
        "servlet": VulnerabilityType.XSS,
        "path": VulnerabilityType.PATH_TRAVERSAL,
        "traversal": VulnerabilityType.PATH_TRAVERSAL,
        "directory": VulnerabilityType.PATH_TRAVERSAL,
        "lfi": VulnerabilityType.PATH_TRAVERSAL,
        "command": VulnerabilityType.COMMAND_INJECTION,
        "cmd": VulnerabilityType.COMMAND_INJECTION,
        "exec": VulnerabilityType.COMMAND_INJECTION,
        "secret": VulnerabilityType.HARDCODED_SECRET,
        "password": VulnerabilityType.HARDCODED_SECRET,
        "hard_code": VulnerabilityType.HARDCODED_SECRET,
        "hardcode": VulnerabilityType.HARDCODED_SECRET,
        "ssrf": VulnerabilityType.SSRF,
        "xxe": VulnerabilityType.XXE,
        "deserial": VulnerabilityType.DESERIALIZATION,
        "permissive_cors": VulnerabilityType.XSS,  # CORS issues can lead to XSS
    }
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the sink verifier.
        
        Args:
            project_root: Optional project root for file lookups
        """
        self.project_root = project_root
    
    def infer_vulnerability_type(self, rule_id: str) -> VulnerabilityType:
        """
        Infer the vulnerability type from a rule ID.
        
        Args:
            rule_id: Semgrep rule ID
            
        Returns:
            Inferred VulnerabilityType
        """
        rule_lower = rule_id.lower()
        
        for pattern, vuln_type in self.RULE_TO_VULN_TYPE.items():
            if pattern in rule_lower:
                return vuln_type
        
        return VulnerabilityType.UNKNOWN
    
    def verify_sink(self, code: str, rule_id: str, 
                    flagged_line: int = 0) -> SinkVerificationResult:
        """
        Verify that the sink matches the vulnerability type.
        
        Args:
            code: Code context around the finding
            rule_id: Semgrep rule ID
            flagged_line: Line number of the flagged code
            
        Returns:
            SinkVerificationResult with verification details
        """
        vuln_type = self.infer_vulnerability_type(rule_id)
        
        if vuln_type == VulnerabilityType.UNKNOWN:
            return SinkVerificationResult(
                is_valid_sink=True,  # Can't verify, assume valid
                vulnerability_type=vuln_type,
                sink_pattern_matched=None,
                safe_transform_detected=None,
                reason="Unknown vulnerability type, cannot verify sink",
                confidence=0.5,
            )
        
        requirements = self.SINK_REQUIREMENTS.get(vuln_type, {})
        required_sinks = requirements.get("required_sinks", [])
        safe_transforms = requirements.get("safe_transforms", [])
        
        # Check for safe transforms first (they override sink checks)
        for transform in safe_transforms:
            if re.search(transform, code, re.IGNORECASE):
                return SinkVerificationResult(
                    is_valid_sink=False,
                    vulnerability_type=vuln_type,
                    sink_pattern_matched=None,
                    safe_transform_detected=transform,
                    reason=f"Safe transform detected: {transform}",
                    confidence=0.9,
                )
        
        # For hardcoded secrets, check for true positive patterns
        if vuln_type == VulnerabilityType.HARDCODED_SECRET:
            true_positive_patterns = requirements.get("true_positive_patterns", [])
            for pattern in true_positive_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return SinkVerificationResult(
                        is_valid_sink=True,
                        vulnerability_type=vuln_type,
                        sink_pattern_matched=pattern,
                        safe_transform_detected=None,
                        reason="Matches hardcoded secret pattern",
                        confidence=0.9,
                    )
            
            # If no true positive pattern, likely false positive
            return SinkVerificationResult(
                is_valid_sink=False,
                vulnerability_type=vuln_type,
                sink_pattern_matched=None,
                safe_transform_detected=None,
                reason="No actual hardcoded secret pattern detected",
                confidence=0.7,
            )
        
        # Check for required sink patterns
        if required_sinks:
            for sink in required_sinks:
                if re.search(sink, code, re.IGNORECASE):
                    return SinkVerificationResult(
                        is_valid_sink=True,
                        vulnerability_type=vuln_type,
                        sink_pattern_matched=sink,
                        safe_transform_detected=None,
                        reason=f"Valid sink pattern matched: {sink}",
                        confidence=0.9,
                    )
            
            # No sink matched
            return SinkVerificationResult(
                is_valid_sink=False,
                vulnerability_type=vuln_type,
                sink_pattern_matched=None,
                safe_transform_detected=None,
                reason=f"No matching {vuln_type.value} sink pattern found",
                confidence=0.7,
            )
        
        # No requirements defined, assume valid
        return SinkVerificationResult(
            is_valid_sink=True,
            vulnerability_type=vuln_type,
            sink_pattern_matched=None,
            safe_transform_detected=None,
            reason="No sink requirements defined for this vulnerability type",
            confidence=0.5,
        )
    
    def verify_xss_output_context(self, code: str, variable_name: str) -> tuple[bool, str]:
        """
        Specifically verify XSS by checking if data is rendered in HTML.
        
        Args:
            code: Code context
            variable_name: Variable containing potentially tainted data
            
        Returns:
            (is_xss_risk: bool, reason: str)
        """
        var_pattern = re.escape(variable_name)
        
        # Check if variable is used in safe contexts
        safe_contexts = [
            (rf'{var_pattern}\s*\.equals\s*\(', "Used in equals comparison"),
            (rf'{var_pattern}\s*\.matches\s*\(', "Used in pattern matching"),
            (rf'Integer\.parseInt\s*\(\s*{var_pattern}', "Parsed as integer"),
            (rf'Long\.parseLong\s*\(\s*{var_pattern}', "Parsed as long"),
            (rf'Enum\.valueOf\s*\([^,]+,\s*{var_pattern}', "Used for enum lookup"),
            (rf'logger\.[a-z]+\s*\([^)]*{var_pattern}', "Used in logging"),
            (rf'log\.[a-z]+\s*\([^)]*{var_pattern}', "Used in logging"),
        ]
        
        for pattern, reason in safe_contexts:
            if re.search(pattern, code, re.IGNORECASE):
                return False, f"NOT XSS risk: {reason}"
        
        # Check if variable is used in dangerous contexts
        dangerous_contexts = [
            (rf'\.write\s*\([^)]*{var_pattern}', "Written to response"),
            (rf'\.print\s*\([^)]*{var_pattern}', "Printed to response"),
            (rf'innerHTML\s*=\s*[^;]*{var_pattern}', "Set as innerHTML"),
            (rf'\.html\s*\([^)]*{var_pattern}', "Used in jQuery .html()"),
        ]
        
        for pattern, reason in dangerous_contexts:
            if re.search(pattern, code, re.IGNORECASE):
                return True, f"XSS risk: {reason}"
        
        return False, "Variable not used in HTML output context"
    
    def format_verification_for_llm(self, result: SinkVerificationResult) -> str:
        """
        Format sink verification result for LLM consumption.
        
        Args:
            result: SinkVerificationResult to format
            
        Returns:
            Formatted string for inclusion in LLM prompt
        """
        lines = ["## Sink Verification Results\n"]
        
        if result.is_valid_sink:
            lines.append(f"✗ **VALID SINK DETECTED** for {result.vulnerability_type.value}")
            if result.sink_pattern_matched:
                lines.append(f"  - Pattern matched: `{result.sink_pattern_matched}`")
            lines.append(f"  - Confidence: {result.confidence:.0%}")
            lines.append("")
            lines.append("> This finding has a valid sink and may be a TRUE POSITIVE.")
        else:
            lines.append(f"✓ **INVALID/SAFE SINK** for {result.vulnerability_type.value}")
            if result.safe_transform_detected:
                lines.append(f"  - Safe transform: `{result.safe_transform_detected}`")
            lines.append(f"  - Reason: {result.reason}")
            lines.append(f"  - Confidence: {result.confidence:.0%}")
            lines.append("")
            lines.append("> **Recommendation**: This is likely a FALSE POSITIVE as the sink doesn't match the vulnerability type.")
        
        return "\n".join(lines)
