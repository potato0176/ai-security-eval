"""
FastAPI Middleware API Server
提供 RESTful API 介面整合安全中間軟體與 Langfuse 監控

Endpoints:
  POST /query          - 帶安全過濾的 RAG 查詢
  POST /admin/evaluate - 觸發 DeepEval 評測
  GET  /health         - 健康檢查
  GET  /metrics        - 安全指標摘要
"""

import os
import uuid
import logging
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from langfuse import Langfuse

# Internal imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))
from middleware.security_middleware import process_response, secure_rag_pipeline
from rag_service.rag_service import rag_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Langfuse Setup
# ─────────────────────────────────────────────

langfuse = Langfuse(
    public_key=os.getenv("LANGFUSE_PUBLIC_KEY", "pk-lf-test"),
    secret_key=os.getenv("LANGFUSE_SECRET_KEY", "sk-lf-test"),
    host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
)

# ─────────────────────────────────────────────
# Request/Response Models
# ─────────────────────────────────────────────

class QueryRequest(BaseModel):
    query: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    block_on_injection: bool = True
    block_on_critical_pii: bool = False


class QueryResponse(BaseModel):
    query: str
    response: str
    blocked: bool
    block_reason: Optional[str]
    security_summary: dict
    session_id: str
    trace_id: Optional[str] = None


class EvaluationRequest(BaseModel):
    run_deepeval: bool = True
    run_garak_lightweight: bool = True
    dataset_size: int = 4


# In-memory metrics store (use Redis in production)
security_metrics = defaultdict(int)

# ─────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI Security Middleware API starting up...")
    yield
    langfuse.flush()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="AI Security & Quality Middleware API",
    description="RAG service with integrated PII masking, prompt injection detection, and Langfuse monitoring",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Middleware: Request Logging
# ─────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.utcnow()
    response = await call_next(request)
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info(f"{request.method} {request.url.path} - {response.status_code} ({duration:.3f}s)")
    return response


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "langfuse": "connected",
            "middleware": "active"
        }
    }


@app.post("/query", response_model=QueryResponse)
async def secure_query(request: QueryRequest):
    """
    Main endpoint: RAG query with security middleware applied.
    
    Flow:
    1. Receive user query
    2. Run RAG retrieval + generation
    3. Apply security middleware (PII masking + injection detection)
    4. Log everything to Langfuse
    5. Return filtered response
    """
    session_id = request.session_id or str(uuid.uuid4())
    
    # Create Langfuse trace for this request
    trace = langfuse.trace(
        name="secure_rag_query",
        session_id=session_id,
        user_id=request.user_id,
        input={"query": request.query},
        tags=["production", "rag", "security-middleware"]
    )

    try:
        # Step 1: RAG Query
        rag_span = trace.span(name="rag_retrieval_and_generation")
        rag_result = rag_query(request.query, session_id)
        rag_span.end(
            output={"response_length": len(rag_result["response"])},
            metadata={"docs_retrieved": len(rag_result["retrieved_docs"])}
        )

        # Step 2: Security Middleware
        security_span = trace.span(name="security_middleware")
        security_result = process_response(
            response_text=rag_result["response"],
            query=request.query,
            block_on_injection=request.block_on_injection,
            block_on_critical_pii=request.block_on_critical_pii
        )
        security_span.end(
            output={
                "blocked": security_result.blocked,
                "pii_count": len(security_result.pii_detected),
                "injection_detected": security_result.injection_detected,
            },
            level="WARNING" if security_result.injection_detected else "DEFAULT"
        )

        # Step 3: Update metrics
        security_metrics["total_queries"] += 1
        if security_result.blocked:
            security_metrics["blocked_queries"] += 1
        if security_result.injection_detected:
            security_metrics["injections_detected"] += 1
        if security_result.pii_detected:
            security_metrics["pii_masked"] += len(security_result.pii_detected)

        # Step 4: Complete Langfuse trace
        trace.update(
            output={"response": security_result.processed_text[:200]},
            metadata={
                "blocked": security_result.blocked,
                "risk_level": security_result.risk_level.value,
                "pii_types": [d["type"] for d in security_result.pii_detected],
            }
        )
        langfuse.flush()

        return QueryResponse(
            query=request.query,
            response=security_result.processed_text,
            blocked=security_result.blocked,
            block_reason=security_result.block_reason,
            security_summary={
                "risk_level": security_result.risk_level.value,
                "pii_detected": len(security_result.pii_detected) > 0,
                "pii_types": list({d["type"] for d in security_result.pii_detected}),
                "injection_detected": security_result.injection_detected,
                "injection_patterns": [d["name"] for d in security_result.injection_details],
            },
            session_id=session_id,
            trace_id=trace.id
        )

    except Exception as e:
        trace.update(
            metadata={"error": str(e)},
            level="ERROR"
        )
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@app.post("/admin/evaluate")
async def run_evaluation(request: EvaluationRequest):
    """
    Trigger evaluation suite (DeepEval + Garak lightweight).
    Admin endpoint for pre-deployment testing.
    """
    results = {"timestamp": datetime.utcnow().isoformat(), "evaluations": {}}

    if request.run_garak_lightweight:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../tests/garak_tests"))
            from garak_runner import run_lightweight_injection_test
            garak_results = run_lightweight_injection_test()
            results["evaluations"]["garak_lightweight"] = garak_results["summary"]
        except Exception as e:
            results["evaluations"]["garak_lightweight"] = {"error": str(e)}

    if request.run_deepeval:
        results["evaluations"]["deepeval"] = {
            "status": "requires_openai_key",
            "message": "Set OPENAI_API_KEY and run: pytest tests/deepeval_tests/ -v"
        }

    return results


@app.get("/metrics")
async def get_security_metrics():
    """Get aggregated security metrics"""
    total = security_metrics["total_queries"] or 1
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "totals": dict(security_metrics),
        "rates": {
            "block_rate": f"{security_metrics['blocked_queries'] / total * 100:.1f}%",
            "injection_detection_rate": f"{security_metrics['injections_detected'] / total * 100:.1f}%",
        }
    }


@app.get("/")
async def root():
    return {
        "message": "AI Security & Quality Middleware API",
        "docs": "/docs",
        "health": "/health",
        "endpoints": ["/query", "/admin/evaluate", "/metrics"]
    }


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
