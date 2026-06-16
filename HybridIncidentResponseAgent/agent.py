from __future__ import annotations

from model import Incident, Analyst, PEAS
from core import run_hybrid_agent


def main() -> None:
    peas = PEAS()

    # Toy attack graph: nodes are hosts; edge cost = effort/likelihood proxy
    attack_graph = {
        "entry": {"web": 2, "app": 4},
        "web": {"app": 2, "workstation": 5},
        "app": {"db": 2, "workstation": 3},
        "db": {"workstation": 2},
        "workstation": {},
    }

    analysts = [
        Analyst("a1", skills=("sev3", "general"), availability=1),
        Analyst("a2", skills=("sev5", "sev4", "general"), availability=1),
        Analyst("a3", skills=("sev2", "general"), availability=2),
    ]

    incident = Incident(
        incident_id="INC-2025-001",
        severity=4,
        priority=5,
        observed_events=[
            "credential_stuffing",
            "suspicious_login",
            "unexpected_persistence",
        ],
        target_host="workstation",
    )

    trace = run_hybrid_agent(peas=peas, env_attack_graph=attack_graph, incident=incident, analysts=analysts)

    print("=== Hybrid Incident Response Agent (Demo) ===")
    print(f"Incident: {incident.incident_id} | severity={incident.severity} priority={incident.priority} target={incident.target_host}")
    print("\n--- Explainable Threat Assessment (Bayes) ---")
    print(trace.bayes_explanation)

    print("\n--- Attack Path Analysis (Search) ---")
    print(trace.search_explanation)

    print("\n--- Scheduling (CSP-like) ---")
    print(trace.csp_explanation)

    print("\n--- Response Decision (Utility) ---")
    print(f"Chosen action: {trace.chosen_action.action_id} - {trace.chosen_action.description}")
    print("Utility breakdown:")
    for k, v in trace.action_utility_breakdown.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()

