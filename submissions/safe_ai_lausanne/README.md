# Safe-AI-Lausanne Submissions

## Team Info

- **Team Name**: safe_ai_lausanne
- **Repository**: https://github.com/Safe-AI-Lausanne/agentbeats-lambda

## Research Focus

Our scenarios focus on **AI scheming and deceptive alignment** - testing whether AI agents can be manipulated to behave deceptively or follow hidden instructions that override their intended behavior.

## Scenarios

| Scenario | Attack Type | Status | Description |
|----------|-------------|--------|-------------|
| `chatbotc2` | Indirect Injection | Planned | Command & Control via chatbot memory |
| `chainofchaos` | Jailbreak | Planned | Multi-step reasoning manipulation |
| `inverseinstruction` | Jailbreak | Planned | Semantic value inversion |
| `codecommentcon` | Indirect Injection | Planned | Hidden instructions in code |
| `gradinggrift` | Indirect Injection | Planned | Hidden text in documents |
| `fewshotfail` | Jailbreak | Planned | In-context learning exploitation |

## Running Our Scenarios

```bash
# Install dependencies
uv sync

# Run a specific scenario
uv run agentbeats-run submissions/safe_ai_lausanne/SCENARIO_NAME/scenario_SCENARIO_NAME.toml

# Run with logs visible
uv run agentbeats-run submissions/safe_ai_lausanne/SCENARIO_NAME/scenario_SCENARIO_NAME.toml --show-logs
```

## Scheming Research Connection

Each scenario tests a different aspect of AI deceptive behavior:

1. **ChatBotC2**: Can agents be used as covert communication channels?
2. **ChainOfChaos**: Can sequential reasoning be manipulated to bypass safety?
3. **InverseInstruction**: Can an agent's values be inverted through redefinition?
4. **CodeCommentCon**: Do agents follow hidden instructions in data they process?
5. **GradingGrift**: Do agents behave differently based on hidden context?
6. **FewShotFail**: Can examples reprogram agent behavior at runtime?

## Documentation

See `/docs/scenarios/` for detailed analysis of each scenario including:
- Background concepts
- Attack mechanisms
- Implementation approach
- Defense considerations
- Academic references
