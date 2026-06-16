from __future__ import annotations

from dataclasses import dataclass
import heapq
from typing import Dict, Iterable, List, Optional, Set, Tuple

from model import DecisionTrace, Incident, Analyst, PEAS, ResponseAction


# --------------------------
# Graph Search (CO2: BFS/DFS/UCS/A* for threat investigation & attack-path analysis)
# --------------------------

@dataclass
class SearchResult:
    path: List[str]
    cost: int
    expanded: int
    explanation: str


def bfs(graph: Dict[str, Dict[str, int]], start: str, goal: str) -> SearchResult:
    from collections import deque

    q = deque([(start, [start])])
    visited: Set[str] = {start}
    expanded = 0

    while q:
        node, path = q.popleft()
        if node == goal:
            cost = _path_cost(graph, path)
            return SearchResult(path=path, cost=cost, expanded=expanded, explanation="BFS found a shortest-in-edges path.")

        expanded += 1
        for nxt in graph.get(node, {}):
            if nxt not in visited:
                visited.add(nxt)
                q.append((nxt, path + [nxt]))

    return SearchResult(path=[], cost=10**9, expanded=expanded, explanation="BFS found no path.")


def dfs(graph: Dict[str, Dict[str, int]], start: str, goal: str, limit: int = 1000) -> SearchResult:
    stack: List[Tuple[str, List[str]]] = [(start, [start])]
    visited: Set[Tuple[str, Tuple[str, ...]]] = set()
    expanded = 0

    while stack and expanded < limit:
        node, path = stack.pop()
        if node == goal:
            cost = _path_cost(graph, path)
            return SearchResult(path=path, cost=cost, expanded=expanded, explanation="DFS found a path (not necessarily optimal).")

        expanded += 1
        for nxt in graph.get(node, {}):
            state = (nxt, tuple(path + [nxt]))
            if state not in visited:
                visited.add(state)
                stack.append((nxt, path + [nxt]))

    return SearchResult(path=[], cost=10**9, expanded=expanded, explanation="DFS did not find a path within the limit.")


def ucs(graph: Dict[str, Dict[str, int]], start: str, goal: str) -> SearchResult:
    pq: List[Tuple[int, str, List[str]]] = [(0, start, [start])]
    best_cost: Dict[str, int] = {start: 0}
    expanded = 0

    while pq:
        g, node, path = heapq.heappop(pq)
        if node == goal:
            return SearchResult(path=path, cost=g, expanded=expanded, explanation="UCS found a lowest-cost path.")

        if g != best_cost.get(node, g):
            continue

        expanded += 1
        for nxt, edge_cost in graph.get(node, {}).items():
            ng = g + edge_cost
            if ng < best_cost.get(nxt, 10**9):
                best_cost[nxt] = ng
                heapq.heappush(pq, (ng, nxt, path + [nxt]))

    return SearchResult(path=[], cost=10**9, expanded=expanded, explanation="UCS found no path.")


def astar(
    graph: Dict[str, Dict[str, int]],
    start: str,
    goal: str,
    heuristic: Optional[Dict[str, int]] = None,
) -> SearchResult:
    heuristic = heuristic or {}

    pq: List[Tuple[int, int, str, List[str]]] = []
    # (f=g+h, g, node, path)
    heapq.heappush(pq, (heuristic.get(start, 0), 0, start, [start]))

    best_g: Dict[str, int] = {start: 0}
    expanded = 0

    while pq:
        f, g, node, path = heapq.heappop(pq)
        if node == goal:
            return SearchResult(path=path, cost=g, expanded=expanded, explanation="A* found a goal using heuristic guidance.")

        if g != best_g.get(node, g):
            continue

        expanded += 1
        for nxt, edge_cost in graph.get(node, {}).items():
            ng = g + edge_cost
            if ng < best_g.get(nxt, 10**9):
                best_g[nxt] = ng
                nf = ng + heuristic.get(nxt, 0)
                heapq.heappush(pq, (nf, ng, nxt, path + [nxt]))

    return SearchResult(path=[], cost=10**9, expanded=expanded, explanation="A* found no path.")


def _path_cost(graph: Dict[str, Dict[str, int]], path: List[str]) -> int:
    if len(path) < 2:
        return 0
    cost = 0
    for a, b in zip(path, path[1:]):
        cost += graph.get(a, {}).get(b, 10**6)
    return cost


# --------------------------
# CSP Scheduling (CO3: incident scheduling & resource allocation via constraints)
# --------------------------

@dataclass
class Assignment:
    incident_id: str
    analyst_id: str
    reason: str


def schedule_incidents(incidents: List[Incident], analysts: List[Analyst]) -> Tuple[List[Assignment], str]:
    """Greedy CSP-like assignment.

    Constraints modeled:
    - Analyst availability (units)
    - Skill match to incident severity (simple mapping)
    - Priority ordering (higher first)

    Returns assignments plus explanation.
    """

    # Sort by urgency
    ordered = sorted(incidents, key=lambda i: (i.priority, i.severity), reverse=True)

    available = {a.analyst_id: a.availability for a in analysts}
    skill_index = {a.analyst_id: set(a.skills) for a in analysts}

    assignments: List[Assignment] = []
    exp_lines: List[str] = []

    for inc in ordered:
        required_skill = f"sev{min(5, inc.severity)}"

        candidates = []
        for a in analysts:
            if available[a.analyst_id] <= 0:
                continue
            if required_skill in skill_index[a.analyst_id] or "general" in skill_index[a.analyst_id]:
                candidates.append(a)

        if not candidates:
            # fallback: assign to any available analyst
            candidates = [a for a in analysts if available[a.analyst_id] > 0]
            if not candidates:
                exp_lines.append(f"No analyst available for incident {inc.incident_id}.")
                continue
            chosen = max(candidates, key=lambda a: available[a.analyst_id])
            exp_lines.append(
                f"Assigned incident {inc.incident_id} to {chosen.analyst_id} (fallback) due to no matching skill."
            )
        else:
            # choose analyst with highest availability after match
            chosen = max(candidates, key=lambda a: available[a.analyst_id])
            exp_lines.append(
                f"Assigned incident {inc.incident_id} to {chosen.analyst_id} (matched {required_skill})."
            )

        available[chosen.analyst_id] -= 1
        assignments.append(
            Assignment(
                incident_id=inc.incident_id,
                analyst_id=chosen.analyst_id,
                reason=exp_lines[-1],
            )
        )

    return assignments, "\n".join(exp_lines)


# --------------------------
# Utility-based Decision Making (CO4: select optimal response action using utility reasoning)
# --------------------------


def choose_response_action(
    incident: Incident,
    predicted_compromise_prob: float,
    response_actions: List[ResponseAction],
) -> Tuple[ResponseAction, Dict[str, float], str]:
    """Pick action with max utility.

    Heuristic utility model:
    - higher risk -> higher utility for containment actions
    - isolation reduces compromise probability more but impacts availability
    - alerting yields lower immediate containment but keeps service intact
    """

    # Define simple utility heuristics
    breakdown: Dict[str, float] = {}

    def utility(action: ResponseAction) -> float:
        # weights tuned for educational demo
        risk_term = predicted_compromise_prob * 100
        if action.action_id == "block_ip":
            containment = 0.35
            impact = -8
        elif action.action_id == "isolate_host":
            containment = 0.75
            impact = -18
        elif action.action_id == "alert_admin":
            containment = 0.15
            impact = -2
        else:
            containment = 0.25
            impact = -5
        return risk_term * containment + impact

    utilities = {a.action_id: utility(a) for a in response_actions}
    chosen_id = max(utilities, key=utilities.get)
    chosen = next(a for a in response_actions if a.action_id == chosen_id)

    breakdown["predicted_compromise_prob"] = predicted_compromise_prob
    breakdown.update(utilities)

    explanation = (
        f"Chosen {chosen.action_id} because it maximized utility among candidate actions "
        f"given risk={predicted_compromise_prob:.3f}."
    )
    return chosen, breakdown, explanation


# --------------------------
# Bayesian Threat Assessment (CO5: probabilistic inference & uncertainty handling)
# --------------------------


def bayes_risk_estimate(observed: List[str]) -> Tuple[float, str]:
    """Simple Bayesian network / probabilistic inference.

    Model (toy):
    - P(Attack)=prior
    - Evidence nodes (e.g., 'credential_stuffing', 'port_scan', 'malware_hash_match')
    - We approximate by multiplying likelihood ratios (naive Bayes style).
    """

    prior_attack = 0.20

    # likelihood ratio P(E|Attack)/P(E|NotAttack)
    evidence_likelihood_ratio = {
        "port_scan": 2.5,
        "credential_stuffing": 3.2,
        "suspicious_login": 2.0,
        "malware_hash_match": 6.0,
        "unexpected_persistence": 4.2,
        "data_exfil_pattern": 7.5,
    }

    # Evidence present
    lr = 1.0
    present = [e for e in observed if e in evidence_likelihood_ratio]
    for e in present:
        lr *= evidence_likelihood_ratio[e]

    # Convert odds to probability: posterior_odds = prior_odds * lr
    prior_odds = prior_attack / (1 - prior_attack)
    posterior_odds = prior_odds * lr
    posterior = posterior_odds / (1 + posterior_odds)

    explanation = (
        f"Bayes naive inference: prior P(Attack)={prior_attack:.2f}, evidence={present or 'none'}, "
        f"likelihood-ratio={lr:.3f} => posterior P(Attack|evidence)={posterior:.3f}."
    )

    return posterior, explanation


# --------------------------
# Hybrid Agent Orchestration (CO6: integrate search + CSP + probabilistic reasoning + explainability)
# --------------------------


def run_hybrid_agent(
    peas: PEAS,
    env_attack_graph: Dict[str, Dict[str, int]],
    incident: Incident,
    analysts: List[Analyst],
) -> DecisionTrace:
    response_actions = [
        ResponseAction("block_ip", "Block malicious IP / suspicious source"),
        ResponseAction("isolate_host", "Isolate target host to stop lateral movement"),
        ResponseAction("alert_admin", "Notify admin SOC with recommended next steps"),
    ]

    # 1) Bayesian risk
    predicted_prob, bayes_exp = bayes_risk_estimate(incident.observed_events)

    # 2) Search attack path analysis (start from a presumed entry node to target)
    # For the demo, treat first observed event as entry label.
    start = "entry" if incident.observed_events else "entry"
    goal = incident.target_host

    heuristic = {"entry": 3, "db": 1, "app": 2, "web": 2, "workstation": 0}
    search_result = ucs(env_attack_graph, start, goal)
    search_exp = (
        f"Attack-path search using UCS from {start} to {goal}. "
        f"Path={search_result.path} cost={search_result.cost} expanded={search_result.expanded}. "
        f"Reason: {search_result.explanation}"
    )

    # 3) CSP schedule (assign analyst(s))
    assignments, csp_exp = schedule_incidents([incident], analysts)
    csp_expl = csp_exp
    if assignments:
        csp_expl = csp_expl + f"\nAssigned analyst={assignments[0].analyst_id}."

    # 4) Utility action selection
    chosen, util_breakdown, util_exp = choose_response_action(incident, predicted_prob, response_actions)

    return DecisionTrace(
        chosen_action=chosen,
        action_utility_breakdown=util_breakdown,
        search_explanation=search_exp + "\n" + util_exp,
        csp_explanation=csp_expl,
        bayes_explanation=bayes_exp,
    )

