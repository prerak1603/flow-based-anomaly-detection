"""
================================================================================
AEGIS AI v2 - Threat Analysis Agent (LangGraph)
================================================================================

Module      : agent.py
Description : Multi-step reasoning agent that synthesizes classifier output,
              sliding-window attribution, and RAG-retrieved context into a
              structured WHAT / WHERE / HOW / WHY / RECOMMENDATION report.

Architecture:
  retrieve_context → assess_severity → [conditional: enrich if HIGH/CRITICAL]
  → generate_narrative → determine_recommendation → compile_report

The LLM (Claude Haiku) handles NARRATIVE EXPLANATION only.
Recommendations are RULE-BASED and deterministic — auditable, not
hallucination-prone. This is a deliberate design choice for a security tool.

Author      : Prerak Nain
================================================================================
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # v2/api/

from typing import Dict, List, Optional, TypedDict, Literal
from langgraph.graph import StateGraph, END
from langchain_anthropic import ChatAnthropic


# ==============================================================================
# AGENT STATE — everything the graph nodes share
# ==============================================================================

class AgentState(TypedDict):
    # --- INPUTS (set before the graph runs) ---
    prediction: str              # e.g. "DDoS"
    confidence: float            # e.g. 0.94
    is_attack: bool
    attribution: Dict            # from attribution.py (full or degraded mode)
    row_index: int

    # --- INTERMEDIATE (populated by nodes as they run) ---
    rag_context: List[str]       # chunks retrieved from knowledge base
    rag_enrichment: List[str]    # extra chunks (only for HIGH/CRITICAL)
    severity: str                # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
    severity_reasons: List[str]  # why this severity was assigned

    # --- OUTPUTS (final report components) ---
    narrative: str               # LLM-generated WHAT/WHERE/HOW/WHY explanation
    recommendation: Dict         # rule-based action + LLM justification
    final_report: Dict           # compiled structured output


# ==============================================================================
# SEVERITY RULES — deterministic, not LLM-decided
# ==============================================================================

HIGH_PRECISION_CLASSES = {
    "DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris",
    "DoS Slowhttptest", "PortScan", "FTP-Patator", "SSH-Patator",
}

CRITICAL_CLASSES = {"Heartbleed", "Infiltration"}

ACTION_RULES = {
    "CRITICAL": {
        "action": "BLOCK source immediately + escalate to security team",
        "auto_blockable": True,
        "urgency": "immediate",
    },
    "HIGH": {
        "action": "BLOCK source + schedule investigation within 24 hours",
        "auto_blockable": True,
        "urgency": "within 1 hour",
    },
    "MEDIUM": {
        "action": "FLAG for manual review — do not auto-block",
        "auto_blockable": False,
        "urgency": "within 24 hours",
    },
    "LOW": {
        "action": "LOG for baseline monitoring — no immediate action needed",
        "auto_blockable": False,
        "urgency": "routine",
    },
}


# ==============================================================================
# NODE 1: RETRIEVE CONTEXT (RAG)
# ==============================================================================

def retrieve_context(state: AgentState) -> AgentState:
    """
    Query the RAG knowledge base for information about the detected attack type.
    Retrieves: attack intent, typical targets, historical model performance.
    """
    from app.context.rag import AegisRAG

    rag = AegisRAG()

    prediction = state["prediction"]
    queries = [
        f"What is the intent and typical target of a {prediction} attack?",
        f"How reliable is the model's detection of {prediction}?",
    ]

    chunks = []
    for q in queries:
        results = rag.retrieve(q, k=2)
        chunks.extend(results)

    # Deduplicate while preserving order
    seen = set()
    unique_chunks = []
    for chunk in chunks:
        if chunk not in seen:
            seen.add(chunk)
            unique_chunks.append(chunk)

    state["rag_context"] = unique_chunks[:4]  # cap at 4 chunks to control token cost
    return state


# ==============================================================================
# NODE 2: ASSESS SEVERITY (rule-based, deterministic)
# ==============================================================================

def assess_severity(state: AgentState) -> AgentState:
    """
    Determine threat severity using RULES, not LLM judgment.
    This is deliberately deterministic — auditable, explainable,
    and not subject to hallucination or prompt-sensitivity.
    """
    prediction = state["prediction"]
    confidence = state["confidence"]
    attribution = state["attribution"]
    reasons = []

    # Start with confidence-based baseline
    if confidence >= 0.95:
        base_severity = "HIGH"
        reasons.append(f"High model confidence ({confidence:.1%})")
    elif confidence >= 0.75:
        base_severity = "MEDIUM"
        reasons.append(f"Moderate model confidence ({confidence:.1%})")
    else:
        base_severity = "LOW"
        reasons.append(f"Low model confidence ({confidence:.1%})")

    # Elevate for critical attack classes
    if prediction in CRITICAL_CLASSES:
        base_severity = "CRITICAL"
        reasons.append(f"{prediction} is a critical-severity class")

    # Elevate HIGH → CRITICAL if behavioral signals corroborate
    if base_severity == "HIGH" and attribution.get("mode") == "full":
        ctx = attribution.get("behavioral_context") or {}

        # Very regular timing = automated/scripted (strengthens confidence)
        if ctx.get("timing_regularity_cv", 1) < 0.1:
            base_severity = "CRITICAL"
            reasons.append("Behavioral corroboration: automated timing pattern (CV < 0.1)")

        # 100% failed connections = classic DDoS/scan signature
        if ctx.get("failed_connection_ratio", 0) > 0.9:
            reasons.append("Behavioral corroboration: >90% failed connections")

    # Demote if it's a well-understood, high-precision class with high confidence
    # (reduces noise for classes where the model rarely makes mistakes)
    if prediction in HIGH_PRECISION_CLASSES and confidence >= 0.99:
        reasons.append(f"{prediction} has historically high precision (>99%) at this confidence level")

    state["severity"] = base_severity
    state["severity_reasons"] = reasons
    return state


# ==============================================================================
# CONDITIONAL EDGE: Should we enrich context?
# ==============================================================================

def should_enrich(state: AgentState) -> Literal["enrich", "skip_enrich"]:
    """
    HIGH and CRITICAL severity get EXTRA context retrieval
    (remediation-specific information). LOW/MEDIUM skip this
    to save time and token cost.
    """
    if state["severity"] in ("HIGH", "CRITICAL"):
        return "enrich"
    return "skip_enrich"


# ==============================================================================
# NODE 3: ENRICH CONTEXT (extra RAG, only for HIGH/CRITICAL)
# ==============================================================================

def enrich_context(state: AgentState) -> AgentState:
    """
    For HIGH/CRITICAL threats, retrieve additional remediation-specific
    context from the knowledge base — "what to actually DO about this."
    """
    from app.context.rag import AegisRAG

    rag = AegisRAG()

    prediction = state["prediction"]
    enrichment_queries = [
        f"What is the typical response and remediation for {prediction}?",
        f"What ports and services does {prediction} typically target?",
    ]

    chunks = []
    for q in enrichment_queries:
        results = rag.retrieve(q, k=2)
        chunks.extend(results)

    # Deduplicate against already-retrieved context
    existing = set(state.get("rag_context", []))
    unique_new = [c for c in chunks if c not in existing]

    state["rag_enrichment"] = unique_new[:3]
    return state


# ==============================================================================
# NODE 4: GENERATE NARRATIVE (LLM call — the explanation writer)
# ==============================================================================

def generate_narrative(state: AgentState) -> AgentState:
    """
    Uses the LLM to synthesize all gathered context into a readable
    WHAT / WHERE / HOW / WHY explanation. The LLM is NOT deciding
    what to do — only explaining what was found.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        state["narrative"] = (
            "[LLM unavailable — API key not configured. "
            "Set ANTHROPIC_API_KEY environment variable to enable "
            "AI-generated narrative explanations.]"
        )
        return state

    llm = ChatAnthropic(
        model="claude-haiku-4-5-20251001",
        api_key=api_key,
        max_tokens=400,
        temperature=0.2,
    )

    # Build the attribution section
    attr = state["attribution"]
    if attr.get("mode") == "full" and attr.get("available"):
        ctx = attr.get("behavioral_context") or {}
        attribution_text = (
            f"Source IP: {attr['host_ip']}\n"
            f"Connection count: {ctx.get('connection_count', 'N/A')}\n"
            f"Timing regularity (CV): {ctx.get('timing_regularity_cv', 'N/A')}\n"
            f"Failed connection ratio: {ctx.get('failed_connection_ratio', 'N/A')}\n"
            f"Unique destination ports: {ctx.get('unique_destination_ports', 'N/A')}\n"
            f"Top destination ratio: {ctx.get('top_destination_ratio', 'N/A')}"
        )
    elif attr.get("mode") == "degraded" and attr.get("available"):
        attribution_text = (
            f"Source IP: unavailable (anonymized dataset)\n"
            f"Destination port: {attr.get('destination_port', 'N/A')} "
            f"({attr.get('likely_service', 'unknown')})\n"
            f"Risk note: {attr.get('risk_note', 'none')}"
        )
    else:
        attribution_text = "No attribution data available."

    # Combine RAG chunks
    all_context = state.get("rag_context", []) + state.get("rag_enrichment", [])
    rag_text = "\n---\n".join(all_context) if all_context else "No reference data available."

    prompt = f"""You are a network security analyst AI generating a threat explanation.

CLASSIFICATION RESULT:
  Attack type: {state['prediction']}
  Confidence: {state['confidence']:.1%}
  Severity: {state['severity']}

ATTRIBUTION DATA:
{attribution_text}

REFERENCE KNOWLEDGE:
{rag_text}

Write a concise threat analysis covering:
- WHAT: What type of attack was detected and how confident is the detection
- WHERE: Where the attack originated (if IP available) or what service was targeted (if only port available)
- HOW: What behavioral patterns or network signatures indicate this attack
- WHY: What the likely intent of this attack is (based on reference knowledge)

Be direct and factual. Do not speculate beyond the provided data. If attribution data is limited, say so clearly. Keep the response under 200 words."""

    try:
        response = llm.invoke(prompt)
        state["narrative"] = response.content
    except Exception as e:
        state["narrative"] = f"[LLM call failed: {str(e)}]"

    return state


# ==============================================================================
# NODE 5: DETERMINE RECOMMENDATION (rule-based + LLM justification)
# ==============================================================================

def determine_recommendation(state: AgentState) -> AgentState:
    """
    The RECOMMENDATION ITSELF is rule-based (deterministic, auditable).
    The LLM only writes a one-sentence JUSTIFICATION explaining why
    this action level was chosen — it does NOT decide the action.
    """
    severity = state["severity"]
    rules = ACTION_RULES.get(severity, ACTION_RULES["LOW"])

    # Build the recommendation structure
    recommendation = {
        "severity": severity,
        "severity_reasons": state["severity_reasons"],
        "recommended_action": rules["action"],
        "auto_blockable": rules["auto_blockable"],
        "urgency": rules["urgency"],
    }

    # Add source-specific recommendations if IP is available
    attr = state["attribution"]
    if attr.get("mode") == "full" and attr.get("host_ip"):
        recommendation["target_ip"] = attr["host_ip"]
        recommendation["ip_action"] = (
            f"Block {attr['host_ip']} at firewall/WAF level"
            if rules["auto_blockable"]
            else f"Monitor {attr['host_ip']} — do not block without manual review"
        )
    elif attr.get("mode") == "degraded" and attr.get("destination_port"):
        recommendation["target_port"] = attr["destination_port"]
        recommendation["port_action"] = (
            f"Review access controls on port {attr['destination_port']} "
            f"({attr.get('likely_service', 'unknown service')})"
        )

    # LLM writes a brief justification (optional — degrades gracefully)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        try:
            llm = ChatAnthropic(
                model="claude-haiku-4-5-20251001",
                api_key=api_key,
                max_tokens=80,
                temperature=0.1,
            )
            justification_prompt = (
                f"In one sentence, explain why a {state['prediction']} attack "
                f"at {state['confidence']:.1%} confidence with severity {severity} "
                f"warrants the action: '{rules['action']}'. "
                f"Severity reasons: {', '.join(state['severity_reasons'])}."
            )
            response = llm.invoke(justification_prompt)
            recommendation["justification"] = response.content
        except Exception:
            recommendation["justification"] = None
    else:
        recommendation["justification"] = None

    state["recommendation"] = recommendation
    return state


# ==============================================================================
# NODE 6: COMPILE REPORT (final assembly)
# ==============================================================================

def compile_report(state: AgentState) -> AgentState:
    """Assemble all pieces into the final structured report."""
    state["final_report"] = {
        "classification": {
            "attack_type": state["prediction"],
            "confidence": round(state["confidence"], 4),
            "is_attack": state["is_attack"],
        },
        "severity": {
            "level": state["severity"],
            "reasons": state["severity_reasons"],
        },
        "attribution": state["attribution"],
        "narrative": state["narrative"],
        "recommendation": state["recommendation"],
    }
    return state


# ==============================================================================
# GRAPH CONSTRUCTION
# ==============================================================================

def build_agent_graph() -> StateGraph:
    """
    Construct the LangGraph agent.

    Flow:
      retrieve_context → assess_severity → [HIGH/CRITICAL? → enrich_context]
      → generate_narrative → determine_recommendation → compile_report → END
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("retrieve_context", retrieve_context)
    graph.add_node("assess_severity", assess_severity)
    graph.add_node("enrich_context", enrich_context)
    graph.add_node("generate_narrative", generate_narrative)
    graph.add_node("determine_recommendation", determine_recommendation)
    graph.add_node("compile_report", compile_report)

    # Set entry point
    graph.set_entry_point("retrieve_context")

    # Linear edges
    graph.add_edge("retrieve_context", "assess_severity")

    # Conditional edge: severity decides whether to enrich
    graph.add_conditional_edges(
        "assess_severity",
        should_enrich,
        {
            "enrich": "enrich_context",
            "skip_enrich": "generate_narrative",
        },
    )

    graph.add_edge("enrich_context", "generate_narrative")
    graph.add_edge("generate_narrative", "determine_recommendation")
    graph.add_edge("determine_recommendation", "compile_report")
    graph.add_edge("compile_report", END)

    return graph.compile()


# ==============================================================================
# PUBLIC ENTRY POINT
# ==============================================================================

def analyze_threat(
    prediction: str,
    confidence: float,
    is_attack: bool,
    attribution: Dict,
    row_index: int = 0,
) -> Dict:
    """
    Run the full agent pipeline on a single classified flow.

    Args:
        prediction: The classifier's predicted label (e.g. "DDoS")
        confidence: Model confidence (0-1)
        is_attack: Whether this is an attack (prediction != "BENIGN")
        attribution: Output from attribution.get_attack_context()
        row_index: Which flow row this refers to

    Returns:
        Complete structured report dict
    """
    if not is_attack:
        return {
            "classification": {
                "attack_type": "BENIGN",
                "confidence": round(confidence, 4),
                "is_attack": False,
            },
            "severity": {"level": "NONE", "reasons": ["Traffic classified as benign"]},
            "attribution": attribution,
            "narrative": "Traffic classified as benign with no threat indicators.",
            "recommendation": {
                "severity": "NONE",
                "recommended_action": "No action required",
                "auto_blockable": False,
                "urgency": "none",
            },
        }

    # Build initial state
    initial_state: AgentState = {
        "prediction": prediction,
        "confidence": confidence,
        "is_attack": is_attack,
        "attribution": attribution,
        "row_index": row_index,
        "rag_context": [],
        "rag_enrichment": [],
        "severity": "",
        "severity_reasons": [],
        "narrative": "",
        "recommendation": {},
        "final_report": {},
    }

    # Run the graph
    agent = build_agent_graph()
    result = agent.invoke(initial_state)

    return result["final_report"]


# ==============================================================================
# STANDALONE TEST
# ==============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("AEGIS AI AGENT — STANDALONE TEST")
    print("=" * 70)

    # Simulate a high-confidence DDoS detection with full IP attribution
    test_attribution_full = {
        "mode": "full",
        "available": True,
        "host_ip": "203.0.113.45",
        "behavioral_context": {
            "connection_count": 847,
            "timing_regularity_cv": 0.03,
            "external_traffic_ratio": 0.0,
            "unique_destination_ports": 1,
            "port_scan_signature": 0.0,
            "failed_connection_ratio": 1.0,
            "top_destination_ratio": 1.0,
        },
    }

    print("\n--- TEST 1: DDoS with full IP attribution ---")
    result1 = analyze_threat(
        prediction="DDoS",
        confidence=0.9998,
        is_attack=True,
        attribution=test_attribution_full,
    )
    import json
    print(json.dumps(result1, indent=2, default=str))

    # Simulate a degraded-mode detection (no IP, port only)
    test_attribution_degraded = {
        "mode": "degraded",
        "available": True,
        "host_ip": None,
        "destination_port": 22,
        "likely_service": "SSH",
        "risk_note": "credential/brute-force target",
        "disclosure": "Source IP attribution unavailable...",
    }

    print("\n--- TEST 2: SSH-Patator with port-only attribution ---")
    result2 = analyze_threat(
        prediction="SSH-Patator",
        confidence=0.87,
        is_attack=True,
        attribution=test_attribution_degraded,
    )
    print(json.dumps(result2, indent=2, default=str))

    print("\n--- TEST 3: BENIGN (should short-circuit) ---")
    result3 = analyze_threat(
        prediction="BENIGN",
        confidence=0.9995,
        is_attack=False,
        attribution={"mode": "degraded", "available": False},
    )
    print(json.dumps(result3, indent=2, default=str))