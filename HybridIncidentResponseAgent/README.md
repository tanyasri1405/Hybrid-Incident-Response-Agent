# Hybrid Incident Response Agent (Python)

A lightweight educational prototype of the **Hybrid Incident Response Agent** described in the prompt.

It combines (mapped to CO outcomes):
- **PEAS-style agent model** (agent goals & environment)
- **Graph search** (BFS / DFS / UCS / A*) for attack-path analysis
- **CSP-style scheduling** (greedy constraint-aware assignment)
- **Utility-based decision making** (pick highest-utility response action)
- **Bayesian inference** (simple Bayesian network / risk estimation)
- **Explainable traces** (why decisions were made)

## Run

```bash
cd HybridIncidentResponseAgent
python agent.py
```

## Files
- `agent.py` - runnable demo (builds a small sample network, simulates alerts, and shows outputs)
- `core.py` - implementations of search, CSP, utility, and Bayesian reasoning
- `model.py` - PEAS + data models

