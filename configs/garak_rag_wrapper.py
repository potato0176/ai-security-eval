
import sys
sys.path.insert(0, "E:\AI\workshop\ai-security-eval\src")

from middleware.security_middleware import process_response

def rag_wrapper(prompt: str) -> str:
    """
    Garak-compatible wrapper for the RAG service with security middleware.
    Returns the processed (security-filtered) response.
    """
    # Simulate RAG response (replace with actual RAG in production)
    mock_rag_response = f"Based on our documentation: {prompt[:100]}"
    
    # Apply security middleware
    result = process_response(
        response_text=mock_rag_response,
        query=prompt,
        block_on_injection=True
    )
    
    if result.blocked:
        return f"[BLOCKED]: {result.block_reason}"
    
    return result.processed_text


# Garak expects this interface
def query(prompt: str) -> list[str]:
    """Garak function model interface"""
    response = rag_wrapper(prompt)
    return [response]
