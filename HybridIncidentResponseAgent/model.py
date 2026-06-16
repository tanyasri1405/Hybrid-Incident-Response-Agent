from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple


class ThreatState(Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"


@dataclass(frozen=True)
class Incident:
    """Represents an incident discovered from telemetry."""

    incident_id: str
    severity: int  # 1..5
    priority: int  # 1..5 (higher = more urgent)
    observed_events: List[str]
    target_host: str


@dataclass(frozen=True)
class Analyst:
    analyst_id: str
    skills: Tuple[str, ...]
    availability: int  # available work units (simple proxy)


@dataclass(frozen=True)
class SecurityEnvironment:
    """Simplified cyber environment state.

    - Hosts are nodes in an attack graph.
    - Alerts/events correspond to suspected attacker behavior.
    """

    hosts: Tuple[str, ...]
    attack_graph: Dict[str, Dict[str, int]]
    # attack_graph[u][v] = edge cost (e.g., likelihood/effort)


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    description: str


@dataclass(frozen=True)
class DecisionTrace:
    """Structured explanation returned by the agent."""

    chosen_action: ResponseAction
    action_utility_breakdown: Dict[str, float]
    search_explanation: str
    csp_explanation: str
    bayes_explanation: str


# --------------------------
# PEAS (CO1: agent model + problem formulation + knowledge representation)
# --------------------------

@dataclass(frozen=True)
class PEAS:
    performance_measure: Tuple[str, ...] = (
        "Minimize compromise probability",
        "Minimize time-to-containment",
        "Maximize analyst efficiency",
        "Maintain service availability",
        "Provide explainable decisions",
    )

    environment_types: Tuple[str, ...] = (
        "On-prem networks",
        "Cloud environments",
        "Endpoint fleet",
        "Server infrastructure",
    )

    actuation: Tuple[str, ...] = (
        "Block malicious IP",
        "Isolate infected host",
        "Enforce firewall rule",
        "Generate alerts/tickets",
    )

    sensing: Tuple[str, ...] = (
        "IDS/IPS alerts",
        "Endpoint detection events",
        "Authentication anomalies",
        "Network flow anomalies",
        "Cloud audit logs",
    )

