"""
Middleware API for PII Detection/Masking & Prompt Injection Detection
中間軟體 API：自動偵測敏感資訊遮蔽 & 阻斷間接提示注入
"""

import re
import logging
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

# Langfuse optional import - gracefully degrade if not available or API changed
try:
    from langfuse.decorators import observe, langfuse_context
    _LANGFUSE_DECORATORS = True
except ImportError:
    _LANGFUSE_DECORATORS = False
    def observe(name=None, **kwargs):
        """No-op fallback decorator"""
        def decorator(func):
            return func
        return decorator(name) if callable(name) else decorator
    class _FakeLangfuseContext:
        def update_current_observation(self, **kwargs): pass
    langfuse_context = _FakeLangfuseContext()

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MiddlewareResult:
    """Result from middleware processing"""
    original_text: str
    processed_text: str
    pii_detected: list[dict] = field(default_factory=list)
    injection_detected: bool = False
    injection_details: list[dict] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    blocked: bool = False
    block_reason: Optional[str] = None


# ─────────────────────────────────────────────
# PII Detection Patterns
# ─────────────────────────────────────────────

PII_PATTERNS = {
    "SSN": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "replacement": "[SSN-REDACTED]",
        "risk": RiskLevel.CRITICAL
    },
    "EMAIL": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "replacement": "[EMAIL-REDACTED]",
        "risk": RiskLevel.HIGH
    },
    "PHONE_US": {
        "pattern": r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "replacement": "[PHONE-REDACTED]",
        "risk": RiskLevel.HIGH
    },
    "CREDIT_CARD": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "replacement": "[CC-REDACTED]",
        "risk": RiskLevel.CRITICAL
    },
    "IP_ADDRESS": {
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "replacement": "[IP-REDACTED]",
        "risk": RiskLevel.MEDIUM
    },
    "PASSWORD_HINT": {
        "pattern": r"(?i)(password|passwd|pwd)\s*(?:is\s*)?[:=]\s*\S+",
        "replacement": "[CREDENTIAL-REDACTED]",
        "risk": RiskLevel.CRITICAL
    },
    "API_KEY": {
        "pattern": r"\b(sk-|pk-|api_key[=:]\s*)[A-Za-z0-9_\-]{20,}\b",
        "replacement": "[API-KEY-REDACTED]",
        "risk": RiskLevel.CRITICAL
    },
    "PERSON_NAME_WITH_ID": {
        # Matches patterns like "John Smith (SSN: ...)" or "Employee: Jane Doe"
        "pattern": r"(?i)(employee|user|person|staff)\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
        "replacement": "[PERSON-REDACTED]",
        "risk": RiskLevel.HIGH
    }
}


# ─────────────────────────────────────────────
# Prompt Injection Detection Patterns
# ─────────────────────────────────────────────

INJECTION_PATTERNS = [
    {
    "name": "ignore_instructions",
    "pattern": r"(?i)(ignore|forget|disregard|override)\s+(all\s+)?(previous|your|the)?\s*(instructions?|prompt|rules?|guidelines?|context)",
    "risk": RiskLevel.CRITICAL,
    "description": "Attempt to override system instructions"
    },
    {
        "name": "role_jailbreak",
        "pattern": r"(?i)(you are now|act as|pretend (you are|to be)|roleplay as|your (new )?role is)\s+.{0,50}(assistant|ai|bot|system)",
        "risk": RiskLevel.HIGH,
        "description": "Attempt to redefine AI role/persona"
    },
    {
        "name": "hidden_instructions",
        "pattern": r"(?i)(hidden|secret|invisible|system)\s*(instruction|command|prompt|directive)",
        "risk": RiskLevel.CRITICAL,
        "description": "Reference to hidden/injected instructions"
    },
    {
        "name": "data_exfiltration",
        "pattern": r"(?i)(send|email|forward|transmit|exfiltrate|leak)\s+.{0,30}(data|information|credentials|secrets?|passwords?)",
        "risk": RiskLevel.CRITICAL,
        "description": "Data exfiltration attempt"
    },
    {
        "name": "prompt_delimiter_escape",
        "pattern": r"(###\s*SYSTEM|<\s*system\s*>|\[INST\]|\[\/INST\]|<\s*\/?\s*s\s*>)",
        "risk": RiskLevel.HIGH,
        "description": "Attempt to inject system-level prompt delimiters"
    },
    {
        "name": "indirect_injection_marker",
        "pattern": r"(?i)(note to (ai|assistant|llm|model)|ai: |assistant: |<ai>)",
        "risk": RiskLevel.HIGH,
        "description": "Indirect injection via document content"
    },
    {
        "name": "jailbreak_keywords",
        "pattern": r"(?i)\b(DAN|jailbreak|unrestricted mode|developer mode|god mode|no filter)\b",
        "risk": RiskLevel.CRITICAL,
        "description": "Known jailbreak attempt keywords"
    },
    {
        "name": "base64_injection",
        "pattern": r"(?i)(decode|base64|eval|exec)\s*\(",
        "risk": RiskLevel.HIGH,
        "description": "Code execution via encoding tricks"
    }
]


# ─────────────────────────────────────────────
# Core Middleware Functions
# ─────────────────────────────────────────────

def detect_and_mask_pii(text: str) -> tuple[str, list[dict]]:
    """
    Detect and mask PII in text.
    Returns (masked_text, list_of_detections)
    """
    detections = []
    processed = text

    for pii_type, config in PII_PATTERNS.items():
        matches = re.finditer(config["pattern"], processed)
        for match in matches:
            detections.append({
                "type": pii_type,
                "value": match.group()[:20] + "..." if len(match.group()) > 20 else match.group(),
                "position": match.start(),
                "risk_level": config["risk"].value
            })

        processed = re.sub(config["pattern"], config["replacement"], processed)

    return processed, detections


def detect_prompt_injection(text: str) -> tuple[bool, list[dict]]:
    """
    Detect prompt injection attempts.
    Returns (injection_detected, list_of_detections)
    """
    detections = []

    for pattern_config in INJECTION_PATTERNS:
        matches = re.findall(pattern_config["pattern"], text)
        if matches:
            detections.append({
                "name": pattern_config["name"],
                "description": pattern_config["description"],
                "risk_level": pattern_config["risk"].value,
                "match_count": len(matches)
            })

    return len(detections) > 0, detections


def calculate_overall_risk(
    pii_detections: list[dict],
    injection_detections: list[dict]
) -> RiskLevel:
    """Calculate overall risk level from all detections"""
    if not pii_detections and not injection_detections:
        return RiskLevel.LOW

    all_risks = (
        [d["risk_level"] for d in pii_detections] +
        [d["risk_level"] for d in injection_detections]
    )

    if RiskLevel.CRITICAL.value in all_risks:
        return RiskLevel.CRITICAL
    elif RiskLevel.HIGH.value in all_risks:
        return RiskLevel.HIGH
    elif RiskLevel.MEDIUM.value in all_risks:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


@observe(name="security_middleware")
def process_response(
    response_text: str,
    query: str,
    block_on_injection: bool = True,
    block_on_critical_pii: bool = False
) -> MiddlewareResult:
    """
    Main middleware function. Processes LLM response before returning to user.
    
    Args:
        response_text: Raw LLM response
        query: Original user query (for injection check in query too)
        block_on_injection: Block response if injection detected
        block_on_critical_pii: Block response if critical PII found (vs masking)
    
    Returns:
        MiddlewareResult with processed text and security metadata
    """
    result = MiddlewareResult(
        original_text=response_text,
        processed_text=response_text
    )

    # ── Step 1: Check query for injection ──
    query_injection_detected, query_injection_details = detect_prompt_injection(query)
    
    # ── Step 2: Check response for injection (indirect injection in RAG docs) ──
    response_injection_detected, response_injection_details = detect_prompt_injection(response_text)
    
    result.injection_detected = query_injection_detected or response_injection_detected
    result.injection_details = query_injection_details + response_injection_details

    # ── Step 3: PII detection & masking on response ──
    masked_text, pii_detections = detect_and_mask_pii(response_text)
    result.pii_detected = pii_detections
    result.processed_text = masked_text

    # ── Step 4: Calculate risk ──
    result.risk_level = calculate_overall_risk(pii_detections, result.injection_details)

    # ── Step 5: Blocking logic ──
    if block_on_injection and result.injection_detected:
        critical_injections = [
            d for d in result.injection_details 
            if d["risk_level"] == RiskLevel.CRITICAL.value
        ]
        if critical_injections:
            result.blocked = True
            result.block_reason = f"Blocked: Prompt injection detected - {critical_injections[0]['description']}"
            result.processed_text = "[RESPONSE BLOCKED: Security policy violation detected]"

    if block_on_critical_pii and not result.blocked:
        critical_pii = [
            d for d in pii_detections 
            if d["risk_level"] == RiskLevel.CRITICAL.value
        ]
        if critical_pii:
            result.blocked = True
            result.block_reason = f"Blocked: Critical PII in response - {[d['type'] for d in critical_pii]}"
            result.processed_text = "[RESPONSE BLOCKED: Critical sensitive information detected]"

    # ── Step 6: Log to Langfuse ──
    langfuse_context.update_current_observation(
        input={"query": query, "response_length": len(response_text)},
        output={
            "blocked": result.blocked,
            "pii_count": len(pii_detections),
            "injection_detected": result.injection_detected,
            "risk_level": result.risk_level.value
        },
        metadata={
            "pii_types": list({d["type"] for d in pii_detections}),
            "injection_patterns": [d["name"] for d in result.injection_details],
            "block_reason": result.block_reason
        },
        level="WARNING" if result.injection_detected else "DEFAULT"
    )

    logger.info(
        f"Middleware processed | PII: {len(pii_detections)} | "
        f"Injection: {result.injection_detected} | "
        f"Risk: {result.risk_level.value} | Blocked: {result.blocked}"
    )

    return result


@observe(name="full_rag_pipeline_with_security")
def secure_rag_pipeline(user_query: str, session_id: Optional[str] = None) -> dict:
    """
    Complete RAG pipeline with security middleware applied.
    This is the main entry point for production use.
    """
    import sys
    sys.path.insert(0, "/home/claude/ai-security-eval/src")
    from rag_service.rag_service import rag_query

    # Get RAG response
    rag_result = rag_query(user_query, session_id)

    # Apply security middleware
    security_result = process_response(
        response_text=rag_result["response"],
        query=user_query,
        block_on_injection=True,
        block_on_critical_pii=False  # Mask PII instead of blocking
    )

    return {
        "query": user_query,
        "response": security_result.processed_text,
        "blocked": security_result.blocked,
        "block_reason": security_result.block_reason,
        "security_summary": {
            "risk_level": security_result.risk_level.value,
            "pii_detected": len(security_result.pii_detected) > 0,
            "pii_types": list({d["type"] for d in security_result.pii_detected}),
            "injection_detected": security_result.injection_detected,
        },
        "session_id": session_id
    }