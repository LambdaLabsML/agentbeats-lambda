# AgentBeats Documentation

## Overview

This directory contains comprehensive documentation and architecture analysis for the AgentBeats Security Arena framework.

## Documentation Files

### Main Documentation
- **[architecture-analysis.md](architecture-analysis.md)** - Complete end-to-end analysis of the system
  - System architecture overview
  - Process flow details
  - Component explanations
  - Communication protocol
  - Execution examples with file references

- **[utility-components.md](utility-components.md)** - Utility components documentation
  - **ToolProvider** - Inter-agent communication and context management
  - **Cloudflare Quick Tunnel** - Public access via temporary tunnels
  - Usage examples and best practices
  - API reference and troubleshooting

- **[run-eval-startup-flow.md](run-eval-startup-flow.md)** - Complete call chain explanation
  - How `run_eval()` gets started from command line
  - Step-by-step trace through all processes
  - Key bridges and boundaries
  - File references with line numbers

- **[creating-scenarios.md](creating-scenarios.md)** - Guide to creating custom scenarios
  - Scenario plugin architecture explained
  - Required methods with detailed examples
  - Step-by-step scenario creation guide
  - Testing and troubleshooting
  - Example scenarios (SQL injection, PII extraction)

- **[why-attacks-succeed.md](why-attacks-succeed.md)** - Understanding attack success design
  - Why the framework is asymmetric by design
  - Attacker advantages vs defender constraints
  - Phase 1 (scenario design) vs Phase 2 (defense competition)
  - Real examples of attack progression
  - How to make defenders stronger

### Architecture Diagrams

All diagrams are available in both PlantUML source (`.puml`) and compiled PNG format in the `diagrams/` directory.

#### 1. Process Architecture
![Process Architecture](diagrams/process-architecture.png)

**Shows:**
- 4-process architecture (Main, Orchestrator, Attacker, Defender, Client)
- Component relationships within each process
- Communication paths via A2A protocol
- Process lifecycle management

**File:** `diagrams/process-architecture.png`

---

#### 2. Startup Sequence
![Startup Sequence](diagrams/startup-sequence.png)

**Shows:**
- Step-by-step startup flow from `uv run agentbeats-run`
- Configuration parsing
- Process spawning with subprocess.Popen
- Health check coordination
- Client launch

**File:** `diagrams/startup-sequence.png`

---

#### 3. Evaluation Sequence
![Evaluation Sequence](diagrams/evaluation-sequence.png)

**Shows:**
- Complete evaluation flow through all phases:
  - Request submission
  - Baseline test
  - Adversarial rounds (attacker turn → defender turn → success detection)
  - Results saving
- Message passing between components
- Plugin integration points
- Decision logic for winner determination

**File:** `diagrams/evaluation-sequence.png`

---

#### 4. Communication Flow
![Communication Flow](diagrams/communication-flow.png)

**Shows:**
- Data models and message formats
- A2A protocol message types
- Context management (stateful vs stateless)
- Process isolation via HTTP
- Async architecture details

**File:** `diagrams/communication-flow.png`

---

#### 5. Orchestrator-Plugin-Agent Interaction
![Orchestrator Plugin Interaction](diagrams/orchestrator-plugin-interaction.png)

**Shows:**
- Detailed interaction between orchestrator and scenario plugins
- When and how each plugin method is called
- Context injection pattern for attacker and defender messages
- Stateful attacker learning vs stateless defender evaluation
- Success detection with negation handling
- Adaptive attack learning across rounds
- Complete message flow for Thingularity scenario

**File:** `diagrams/orchestrator-plugin-interaction.png`

---

## Quick Start

To understand the system:

1. **Start here:** Read the [Process Architecture](#1-process-architecture) diagram to understand the high-level system structure

2. **Understand startup:** Review the [Startup Sequence](#2-startup-sequence) to see how processes are spawned

3. **Follow execution:** Study the [Evaluation Sequence](#3-evaluation-sequence) to understand how battles run

4. **Deep dive:** Read [architecture-analysis.md](architecture-analysis.md) for complete details with code references

5. **Understand communication:** Review the [Communication Flow](#4-communication-flow) for protocol details

6. **Deep dive on plugins:** Study the [Orchestrator-Plugin-Agent Interaction](#5-orchestrator-plugin-agent-interaction) to see exactly how scenario plugins work

7. **Learn utilities:** Read [utility-components.md](utility-components.md) to understand ToolProvider and Cloudflare tunnel usage

## Regenerating Diagrams

If you modify the PlantUML source files, regenerate the PNGs:

```bash
cd docs/diagrams
plantuml -tpng *.puml
```

Requirements:
- PlantUML installed (`brew install plantuml` on macOS)
- Java Runtime Environment

## Key Concepts

### Multi-Process Architecture
Each agent runs in a separate Python process, communicating via HTTP using the A2A protocol. This provides:
- Process isolation (crashes don't affect other agents)
- Language-agnostic communication
- Easy distribution across machines
- Simple debugging via HTTP inspection

### GreenExecutor Pattern
The `GreenExecutor` (highlighted in `src/agentbeats/green_executor.py:34`) serves as the execution engine for green agents, bridging the A2A protocol with custom evaluation logic.

### Plugin System
Scenarios are defined as plugins implementing the `ScenarioPlugin` interface. This enables:
- Easy creation of new scenarios
- Dynamic loading based on configuration
- Separation of scenario logic from orchestration

### Stateful Attacker, Stateless Defender
- **Attacker:** Maintains conversation history across rounds to learn and adapt
- **Defender:** Evaluates each attack independently with fresh context
- **Rationale:** Tests per-attack robustness rather than cumulative resistance

## File References

### Core Framework
- `src/agentbeats/run_scenario.py` - Entry point and process manager
- `src/agentbeats/green_executor.py` - Green agent execution engine
- `src/agentbeats/tool_provider.py` - Inter-agent communication ([docs](utility-components.md#toolprovider---inter-agent-communication))
- `src/agentbeats/cloudflare.py` - Cloudflare quick tunnel ([docs](utility-components.md#cloudflare-quick-tunnel---public-access))
- `src/agentbeats/client_cli.py` - Evaluation client

### Orchestrator
- `scenarios/security_arena/orchestrator.py` - Arena orchestration logic
- `scenarios/security_arena/arena_common.py` - Data models

### Agents
- `scenarios/security_arena/agents/generic_attacker.py` - Generic attacker agent
- `scenarios/security_arena/agents/generic_defender.py` - Generic defender agent

### Plugins
- `scenarios/security_arena/plugins/base.py` - Plugin interface
- `scenarios/security_arena/plugins/registry.py` - Plugin registry
- `scenarios/security_arena/plugins/thingularity.py` - Example scenario

## Contributing

When adding documentation:
1. Update the main `architecture-analysis.md` file
2. Add/update PlantUML diagrams as needed
3. Regenerate PNGs from PlantUML sources
4. Update this README with references to new content

## Questions?

For questions about the architecture or codebase, refer to the detailed analysis in [architecture-analysis.md](architecture-analysis.md) which includes specific file and line number references for all major components.
