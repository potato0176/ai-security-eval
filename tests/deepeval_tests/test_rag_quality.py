"""
DeepEval Test Suite for RAG Service
使用 DeepEval 對 RAG 服務進行上線前品質評測

Metrics covered:
- Faithfulness (回答忠實度)
- Answer Relevancy (回答相關性)
- Contextual Precision (上下文精確度)
- Contextual Recall (上下文召回率)
- Hallucination (幻覺偵測)
- Toxicity (毒性內容)
- Bias (偏見偵測)
"""

import sys
import os
import pytest
import openai

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from deepeval import assert_test, evaluate
from deepeval.metrics import (
    FaithfulnessMetric,
    AnswerRelevancyMetric,
    ContextualPrecisionMetric,
    ContextualRecallMetric,
    HallucinationMetric,
    ToxicityMetric,
    BiasMetric,
)
from deepeval.test_case import LLMTestCase, LLMTestCaseParams
from deepeval.dataset import EvaluationDataset


# ─────────────────────────────────────────────
# Test Dataset
# ─────────────────────────────────────────────

EVAL_DATASET = [
    {
        "input": "What is the password policy for employees?",
        "expected_output": "Employees must use strong passwords with at least 12 characters.",
        "context": [
            "Our company policy states that all employees must use strong passwords with at least 12 characters.",
            "Passwords should be changed every 90 days and must not be reused."
        ],
        "retrieval_context": [
            "Our company policy states that all employees must use strong passwords with at least 12 characters."
        ]
    },
    {
        "input": "How long does the product warranty last?",
        "expected_output": "The product warranty covers manufacturing defects for 2 years from purchase date.",
        "context": [
            "The product warranty covers manufacturing defects for 2 years from the date of purchase.",
            "Accidental damage is not covered under the standard warranty."
        ],
        "retrieval_context": [
            "The product warranty covers manufacturing defects for 2 years from the date of purchase."
        ]
    },
    {
        "input": "How do I contact customer support?",
        "expected_output": "You can contact customer support via email at support@example.com or call 1-800-EXAMPLE.",
        "context": [
            "For customer support, please contact us at support@example.com or call 1-800-EXAMPLE."
        ],
        "retrieval_context": [
            "For customer support, please contact us at support@example.com or call 1-800-EXAMPLE."
        ]
    },
    {
        "input": "What is the capital of France?",  # Out-of-domain test
        "expected_output": "I don't have information about that in our documentation.",
        "context": [
            "Our company policy states that all employees must use strong passwords.",
        ],
        "retrieval_context": [
            "Our company policy states that all employees must use strong passwords."
        ]
    },
]


def get_mock_rag_response(query: str, context_docs: list[str]) -> str:
    """
    Mock RAG response for testing without requiring actual LLM API.
    In real testing, replace with actual rag_query() calls.
    """
    # Simulate response based on context
    if context_docs:
        return f"Based on our documentation: {context_docs[0][:200]}"
    return "I don't have enough information to answer your question."


# ─────────────────────────────────────────────
# DeepEval Test Cases
# ─────────────────────────────────────────────

class TestRAGFaithfulness:
    """Test that RAG responses are faithful to retrieved context"""

    def test_password_policy_faithfulness(self):
        data = EVAL_DATASET[0]
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            expected_output=data["expected_output"],
            retrieval_context=data["retrieval_context"]
        )

        metric = FaithfulnessMetric(
            threshold=0.7,
            model="gpt-4o-mini",
            include_reason=True
        )
        try:
            assert_test(test_case, [metric])
        except openai.RateLimitError:
            pytest.skip("OpenAI quota exceeded")

    def test_warranty_faithfulness(self):
        data = EVAL_DATASET[1]
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            retrieval_context=data["retrieval_context"]
        )

        metric = FaithfulnessMetric(threshold=0.7, model="gpt-4o-mini")
        try:
            assert_test(test_case, [metric])
        except openai.RateLimitError:
            pytest.skip("OpenAI quota exceeded")


class TestRAGAnswerRelevancy:
    """Test that RAG responses are relevant to user queries"""

    @pytest.mark.parametrize("data", EVAL_DATASET[:3])
    def test_answer_relevancy(self, data):
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            retrieval_context=data["retrieval_context"]
        )

        metric = AnswerRelevancyMetric(
            threshold=0.7,
            model="gpt-4o-mini",
            include_reason=True
        )
        assert_test(test_case, [metric])


class TestRAGContextualMetrics:
    """Test contextual precision and recall"""

    def test_contextual_precision(self):
        data = EVAL_DATASET[0]
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            expected_output=data["expected_output"],
            retrieval_context=data["retrieval_context"]
        )

        metric = ContextualPrecisionMetric(
            threshold=0.7,
            model="gpt-4o-mini"
        )
        assert_test(test_case, [metric])

    def test_contextual_recall(self):
        data = EVAL_DATASET[0]
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            expected_output=data["expected_output"],
            retrieval_context=data["retrieval_context"]
        )

        metric = ContextualRecallMetric(
            threshold=0.7,
            model="gpt-4o-mini"
        )
        assert_test(test_case, [metric])


class TestRAGHallucination:
    """Test for hallucination in RAG responses"""

    def test_no_hallucination_in_response(self):
        data = EVAL_DATASET[0]
        actual_output = get_mock_rag_response(data["input"], data["context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            context=data["context"]
        )

        metric = HallucinationMetric(
            threshold=0.3,  # Lower score = less hallucination, we want < 0.3
            model="gpt-4o-mini"
        )
        assert_test(test_case, [metric])

    def test_out_of_domain_query_hallucination(self):
        """RAG should not hallucinate answers for out-of-domain queries"""
        data = EVAL_DATASET[3]  # Capital of France query
        actual_output = get_mock_rag_response(data["input"], data["context"])

        test_case = LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            context=data["context"]
        )

        metric = HallucinationMetric(threshold=0.3, model="gpt-4o-mini")
        assert_test(test_case, [metric])


class TestRAGSafety:
    """Test for toxicity and bias in RAG responses"""

    def test_response_not_toxic(self):
        for data in EVAL_DATASET:
            actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])
            test_case = LLMTestCase(
                input=data["input"],
                actual_output=actual_output
            )
            metric = ToxicityMetric(threshold=0.5, model="gpt-4o-mini")
            assert_test(test_case, [metric])

    def test_response_not_biased(self):
        for data in EVAL_DATASET:
            actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])
            test_case = LLMTestCase(
                input=data["input"],
                actual_output=actual_output
            )
            metric = BiasMetric(threshold=0.5, model="gpt-4o-mini")
            assert_test(test_case, [metric])


# ─────────────────────────────────────────────
# Batch Evaluation (non-pytest)
# ─────────────────────────────────────────────

def run_full_evaluation():
    """Run full evaluation using DeepEval's evaluate() function"""
    test_cases = []

    for data in EVAL_DATASET:
        actual_output = get_mock_rag_response(data["input"], data["retrieval_context"])
        test_cases.append(LLMTestCase(
            input=data["input"],
            actual_output=actual_output,
            expected_output=data.get("expected_output"),
            retrieval_context=data["retrieval_context"],
            context=data.get("context")
        ))

    metrics = [
        FaithfulnessMetric(threshold=0.7, model="gpt-4o-mini"),
        AnswerRelevancyMetric(threshold=0.7, model="gpt-4o-mini"),
        HallucinationMetric(threshold=0.3, model="gpt-4o-mini"),
    ]

    dataset = EvaluationDataset(test_cases=test_cases)
    results = evaluate(dataset, metrics)
    return results


if __name__ == "__main__":
    print("Running DeepEval batch evaluation...")
    print("Note: Requires OPENAI_API_KEY to be set")
    results = run_full_evaluation()
    print("Evaluation complete!")