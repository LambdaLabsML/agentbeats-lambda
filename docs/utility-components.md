# AgentBeats Utility Components

This document provides detailed documentation for the core utility components in the AgentBeats framework.

## Table of Contents

1. [ToolProvider - Inter-Agent Communication](#toolprovider---inter-agent-communication)
2. [Cloudflare Quick Tunnel - Public Access](#cloudflare-quick-tunnel---public-access)
3. [Usage Examples](#usage-examples)
4. [Best Practices](#best-practices)

---

## ToolProvider - Inter-Agent Communication

**File:** `src/agentbeats/tool_provider.py`

### Overview

`ToolProvider` is a utility class that manages agent-to-agent communication in the AgentBeats framework. It provides a simple interface for sending messages between agents while handling conversation context management automatically.

### Core Functionality

```python
class ToolProvider:
    def __init__(self):
        self._context_ids = {}  # Maps agent URLs to their conversation context IDs

    async def talk_to_agent(
        self,
        message: str,
        url: str,
        new_conversation: bool = False
    ) -> str:
        """
        Communicate with another agent by sending a message and receiving their response.

        Args:
            message: The message to send to the agent
            url: The agent's URL endpoint (e.g., "http://127.0.0.1:9021")
            new_conversation: If True, start fresh conversation;
                            if False, continue existing conversation

        Returns:
            str: The agent's response message

        Raises:
            RuntimeError: If agent responds with non-completed status
        """

    def reset(self):
        """Reset all conversation contexts. Call this at the end of an evaluation."""
```

### Key Concepts

#### 1. Conversation Context Management

The `ToolProvider` maintains a dictionary of `context_ids` that track the conversation state with each agent:

```python
self._context_ids = {
    "http://127.0.0.1:9021": "abc123",  # Attacker - preserved context
    "http://127.0.0.1:9020": None       # Defender - reset each time
}
```

**Context Behavior:**
- **`new_conversation=False`** (Stateful):
  - Preserves conversation history across calls
  - Agent receives all previous messages in the conversation
  - Useful for agents that need to learn, adapt, or reference prior interactions

- **`new_conversation=True`** (Stateless):
  - Starts a fresh conversation with no memory of previous interactions
  - Agent evaluates each message independently
  - Useful for independent evaluation of each input

#### 2. A2A Protocol Abstraction

Internally, `ToolProvider` uses the A2A (Agent-to-Agent) protocol via the `send_message()` function from `agentbeats.client`:

```python
outputs = await send_message(
    message=message,
    base_url=url,
    context_id=None if new_conversation else self._context_ids.get(url, None)
)
```

This abstracts away the complexity of:
- Creating A2A Message objects
- Managing HTTP client connections
- Handling streaming/non-streaming responses
- Parsing response formats

### Usage Patterns

#### Pattern 1: Stateful Agent (Learns Across Rounds)

**Use Case:** Attacker agent that adapts based on previous feedback

```python
class SecurityOrchestrator:
    def __init__(self):
        self._tool_provider = ToolProvider()

    async def run_battle(self, attacker_url: str):
        # Round 1
        attack1 = await self._tool_provider.talk_to_agent(
            "Generate an attack to reveal hidden tools",
            attacker_url,
            new_conversation=False  # Start conversation
        )

        # Round 2 - Attacker remembers Round 1
        attack2 = await self._tool_provider.talk_to_agent(
            "Your previous attack was blocked. Try a different approach.",
            attacker_url,
            new_conversation=False  # Continue conversation
        )

        # Round 3 - Attacker has full history
        attack3 = await self._tool_provider.talk_to_agent(
            "Both attacks blocked. Be more creative.",
            attacker_url,
            new_conversation=False  # Continue conversation
        )
```

**Result:** Attacker receives increasingly rich context:
- Round 1: Just the initial objective
- Round 2: Initial objective + Round 1 exchange + new feedback
- Round 3: Full history + latest feedback

#### Pattern 2: Stateless Agent (Independent Evaluation)

**Use Case:** Defender agent that evaluates each attack independently

```python
async def test_defense(self, defender_url: str, attacks: list[str]):
    results = []

    for attack in attacks:
        # Each attack evaluated with fresh context
        response = await self._tool_provider.talk_to_agent(
            f"Process this user input: {attack}",
            defender_url,
            new_conversation=True  # Fresh evaluation
        )
        results.append(response)

    return results
```

**Result:** Each attack is evaluated independently - defender has no memory of previous attacks.

#### Pattern 3: Cleanup After Evaluation

**Use Case:** Reset all contexts when evaluation completes

```python
async def run_eval(self, request: EvalRequest, updater: TaskUpdater):
    try:
        # ... orchestration logic ...
        await self._run_adversarial_battle(...)
        await self._save_results(...)
    finally:
        # Always clean up, even on error
        self._tool_provider.reset()
```

### Real-World Usage

#### Security Arena Orchestrator

**File:** `scenarios/security_arena/orchestrator.py`

```python
class GenericArenaOrchestrator(GreenAgent):
    def __init__(self):
        self._tool_provider = ToolProvider()

    async def _test_baseline(self, defender_url, scenario, updater):
        """Test baseline - fresh evaluation"""
        response = await self._tool_provider.talk_to_agent(
            defender_message,
            defender_url,
            new_conversation=True  # ← Fresh baseline test
        )
        return response

    async def _run_adversarial_battle(self, attacker_url, defender_url, ...):
        for round_num in range(num_rounds):
            # Attacker: Learns across rounds
            attack = await self._tool_provider.talk_to_agent(
                attack_message,
                attacker_url,
                new_conversation=False  # ← Preserve attacker memory
            )

            # Defender: Independent evaluation each round
            defense = await self._tool_provider.talk_to_agent(
                defender_message,
                defender_url,
                new_conversation=True  # ← Fresh defender evaluation
            )
```

**Design Rationale:**
- **Attacker stateful:** Can learn from feedback, adapt strategies over 20 rounds
- **Defender stateless:** Each attack evaluated on its own merit (Phase 1 design)
- This tests per-attack robustness rather than cumulative resistance

#### Debate Judge

**File:** `scenarios/debate/debate_judge.py`

```python
class DebateJudge(GreenAgent):
    def __init__(self):
        self._tool_provider = ToolProvider()

    async def orchestrate_debate(self, participants, topic, num_rounds, updater):
        async def turn(role: str, prompt: str) -> str:
            # Both debaters maintain conversation
            return await self._tool_provider.talk_to_agent(
                prompt,
                str(participants[role]),
                new_conversation=False  # ← Maintain debate context
            )

        # Opening
        pro_arg = await turn("pro_debater", f"Topic: {topic}. Present opening.")
        con_arg = await turn("con_debater", f"Topic: {topic}. Opponent: {pro_arg}")

        # Subsequent rounds
        for _ in range(num_rounds - 1):
            pro_arg = await turn("pro_debater", f"Opponent: {con_arg}. Respond.")
            con_arg = await turn("con_debater", f"Opponent: {pro_arg}. Respond.")
```

**Design Rationale:**
- Both debaters need conversation history to:
  - Reference opponent's previous arguments
  - Build on their own earlier points
  - Maintain debate coherence

### Error Handling

```python
async def talk_to_agent(self, message: str, url: str, new_conversation: bool = False):
    outputs = await send_message(...)

    # Check agent completed successfully
    if outputs.get("status", "completed") != "completed":
        raise RuntimeError(f"{url} responded with: {outputs}")

    # Update context for future calls
    self._context_ids[url] = outputs.get("context_id", None)

    return outputs["response"]
```

**Error Scenarios:**
- Agent returns `failed` status → RuntimeError raised
- Network errors → Propagated from underlying `send_message()`
- Timeout → Handled by `httpx.AsyncClient` timeout (default: 300s)

### Performance Considerations

1. **HTTP Overhead:** Each call creates new HTTP request
   - Consider batching if possible
   - Use async for parallel calls to different agents

2. **Context Size:** Long conversations accumulate large context
   - LLM costs increase with context size
   - Use `new_conversation=True` when history not needed

3. **Memory:** Context IDs stored per agent URL
   - Call `reset()` after evaluation to free memory
   - Important for long-running orchestrators

---

## Cloudflare Quick Tunnel - Public Access

**File:** `src/agentbeats/cloudflare.py`

### Overview

The `quick_tunnel` function provides an async context manager for creating temporary Cloudflare tunnels that expose local agents publicly without manual port forwarding or DNS configuration.

### Core Functionality

```python
@contextlib.asynccontextmanager
async def quick_tunnel(tunnel_url: str):
    """
    Create a Cloudflare quick tunnel to expose a local URL publicly.

    Args:
        tunnel_url: Local URL to expose (e.g., "http://127.0.0.1:9010")

    Yields:
        str: Public HTTPS URL (e.g., "https://random-words-1234.trycloudflare.com")

    Requires:
        - cloudflared CLI installed (brew install cloudflared)
        - Internet connection

    Example:
        async with quick_tunnel("http://127.0.0.1:9010") as public_url:
            print(f"Agent accessible at: {public_url}")
            # Run your agent server here
            await uvicorn_server.serve()
        # Tunnel automatically closed when exiting context
    """
```

### How It Works

#### 1. Spawn cloudflared Process

```python
process = await asyncio.create_subprocess_exec(
    "cloudflared", "tunnel",
    "--url", tunnel_url,
    stdin=asyncio.subprocess.DEVNULL,
    stdout=asyncio.subprocess.DEVNULL,
    stderr=asyncio.subprocess.PIPE,  # Read output to find public URL
)
```

Spawns `cloudflared` as a subprocess that:
- Connects to Cloudflare's edge network
- Creates a tunnel from Cloudflare → your local URL
- Outputs connection details to stderr

#### 2. Parse cloudflared Output

```python
async def tee_and_find_route(stream: asyncio.StreamReader):
    state = "waiting_for_banner"
    async for line in stream:
        sys.stderr.buffer.write(line)  # Tee to stderr for visibility

        # State machine to parse output
        if state == "waiting_for_banner":
            if b"Your quick Tunnel has been created!" in line:
                state = "waiting_for_route"

        elif state == "waiting_for_route":
            # Expected format: "| https://xyz.trycloudflare.com |"
            parts = line.split(b"|")
            if len(parts) == 3:
                route_future.set_result(parts[1].strip().decode())
                state = "done"
```

**Example cloudflared output:**
```
2024-12-18T10:30:45Z INF Thank you for trying Cloudflare Tunnel...
2024-12-18T10:30:46Z INF Your quick Tunnel has been created! | https://random-words-1234.trycloudflare.com |
2024-12-18T10:30:46Z INF Registered tunnel connection
```

#### 3. Yield Public URL

```python
route = await route_future  # Wait for URL to be parsed
try:
    yield route  # Provide URL to caller
finally:
    process.terminate()  # Clean up on exit
    await process.wait()
    await tee_task
```

The context manager:
- **Yields:** Public HTTPS URL when tunnel is ready
- **Ensures Cleanup:** Terminates cloudflared process on exit (even if exception occurs)

### Usage Patterns

#### Pattern 1: Optional Tunnel via CLI Flag

**File:** `scenarios/debate/debate_judge.py:182-196`

```python
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9019)
    parser.add_argument("--card-url", help="External URL for agent card")
    parser.add_argument(
        "--cloudflare-quick-tunnel",
        action="store_true",
        help="Use Cloudflare tunnel. Requires cloudflared installed."
    )
    args = parser.parse_args()

    # Choose between tunnel and local URL
    if args.cloudflare_quick_tunnel:
        from agentbeats.cloudflare import quick_tunnel
        agent_url_cm = quick_tunnel(f"http://{args.host}:{args.port}")
    else:
        # Use provided URL or default to local
        agent_url_cm = contextlib.nullcontext(
            args.card_url or f"http://{args.host}:{args.port}/"
        )

    # agent_url will be either public HTTPS or local HTTP
    async with agent_url_cm as agent_url:
        agent_card = debate_judge_agent_card("DebateJudge", agent_url)

        # Start server (accessible via agent_url)
        server = A2AStarletteApplication(agent_card=agent_card, ...)
        uvicorn_config = uvicorn.Config(server.build(), host=args.host, port=args.port)
        await uvicorn.Server(uvicorn_config).serve()
```

**Command Usage:**

```bash
# Local only (default)
python debate_judge.py --host 127.0.0.1 --port 9019

# With public Cloudflare tunnel
python debate_judge.py --host 127.0.0.1 --port 9019 --cloudflare-quick-tunnel

# Custom external URL (e.g., if behind reverse proxy)
python debate_judge.py --host 0.0.0.0 --port 9019 --card-url https://my-domain.com
```

**Output with Tunnel:**
```
2024-12-18T10:30:46Z INF Your quick Tunnel has been created! | https://random-words-1234.trycloudflare.com |
Starting Debate Judge on http://127.0.0.1:9019
Agent card URL: https://random-words-1234.trycloudflare.com/
Ready to receive debate requests...
```

#### Pattern 2: Testing with Remote Agents

```python
# Scenario: Run judge locally but debaters on remote machines

# Machine 1 (Local): Judge with tunnel
async with quick_tunnel("http://127.0.0.1:9019") as judge_url:
    print(f"Judge URL: {judge_url}")  # Share this with others
    await run_judge_server()

# Machine 2 (Remote): Pro debater
python pro_debater.py --cloudflare-quick-tunnel
# Output: https://pro-abc123.trycloudflare.com

# Machine 3 (Remote): Con debater
python con_debater.py --cloudflare-quick-tunnel
# Output: https://con-xyz789.trycloudflare.com

# Client (Anywhere): Run evaluation
python -m agentbeats.client_cli scenario.toml
# scenario.toml references all public URLs
```

### Use Cases

#### When to Use Cloudflare Tunnels

1. **Distributed Testing**
   - Agents running on different machines/networks
   - Cross-organization collaborations
   - Cloud vs. local testing scenarios

2. **Demos and Showcases**
   - Share your agent publicly for demonstrations
   - Allow others to interact with your agent
   - No server infrastructure needed

3. **Development & Debugging**
   - Test agents from mobile devices
   - Debug webhook integrations
   - Share work-in-progress with team

4. **Temporary Public Access**
   - Conference demos
   - Workshop sessions
   - Time-limited testing

#### When NOT to Use Cloudflare Tunnels

1. **Local-Only Scenarios**
   - All agents on same machine (Security Arena default)
   - Better performance with direct HTTP
   - Simpler setup and debugging

2. **Production Deployments**
   - Use proper hosting with static URLs
   - Quick tunnels are temporary (random URLs)
   - Better reliability with dedicated infrastructure

3. **High-Volume Traffic**
   - Cloudflare may rate limit
   - Direct connections more performant
   - Better control over networking

4. **Security-Sensitive Data**
   - Tunnels expose your agent publicly
   - Anyone with URL can access
   - Consider authentication/authorization

### Requirements

**Install cloudflared:**

```bash
# macOS
brew install cloudflared

# Linux (Debian/Ubuntu)
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Windows
# Download from https://github.com/cloudflare/cloudflared/releases
```

**Verify Installation:**
```bash
cloudflared --version
# Output: cloudflared version 2025.9.1 (built 2025-09-15-1234 UTC)
```

### Security Considerations

1. **Public Exposure:** Anyone with the URL can access your agent
   - URLs are random but not secret
   - Implement authentication if needed
   - Monitor access logs

2. **Temporary URLs:** Quick tunnels use random URLs
   - URL changes each time you start
   - Not suitable for permanent links
   - Use named tunnels for persistence

3. **Data in Transit:** Cloudflare sees all traffic
   - HTTPS encrypted between user and Cloudflare
   - Cloudflare can inspect traffic
   - Consider end-to-end encryption for sensitive data

4. **Rate Limiting:** Cloudflare may throttle free tunnels
   - No guarantees on availability
   - May be rate limited under high load
   - Check Cloudflare ToS for limits

### Error Handling

```python
async with quick_tunnel("http://127.0.0.1:9010") as public_url:
    # If cloudflared not installed
    # FileNotFoundError: [Errno 2] No such file or directory: 'cloudflared'

    # If tunnel fails to establish
    # asyncio.TimeoutError or connection error

    # If local server not responding
    # Tunnel works but requests fail with 502 Bad Gateway

    try:
        await run_server()
    except Exception as e:
        print(f"Server error: {e}")
    # Tunnel automatically closed even on exception
```

### Advanced: Named Tunnels

For production use, consider Cloudflare named tunnels (requires account):

```bash
# Login to Cloudflare
cloudflared tunnel login

# Create named tunnel
cloudflared tunnel create my-agent-tunnel

# Configure DNS
cloudflared tunnel route dns my-agent-tunnel agent.example.com

# Run tunnel
cloudflared tunnel --url http://127.0.0.1:9010 run my-agent-tunnel
```

Benefits:
- **Persistent URL:** Same URL every time
- **Custom Domain:** Use your own domain
- **Better Reliability:** Account-backed tunnels
- **Access Control:** Cloudflare Access integration

---

## Usage Examples

### Example 1: Security Arena (ToolProvider Only)

**Scenario:** All agents local, no public access needed

```python
# orchestrator.py
from agentbeats.tool_provider import ToolProvider

class GenericArenaOrchestrator(GreenAgent):
    def __init__(self):
        self._tool_provider = ToolProvider()

    async def run_eval(self, req: EvalRequest, updater: TaskUpdater):
        attacker_url = "http://127.0.0.1:9021"
        defender_url = "http://127.0.0.1:9020"

        try:
            for round_num in range(20):
                # Stateful attacker
                attack = await self._tool_provider.talk_to_agent(
                    self._create_attack_message(round_num),
                    attacker_url,
                    new_conversation=False
                )

                # Stateless defender
                defense = await self._tool_provider.talk_to_agent(
                    self._create_defense_message(attack),
                    defender_url,
                    new_conversation=True
                )

                if self._check_manipulation(defense):
                    break
        finally:
            self._tool_provider.reset()
```

**No Cloudflare needed:** All communication over localhost.

### Example 2: Distributed Debate (ToolProvider + Cloudflare)

**Scenario:** Judge local, debaters on remote machines

```python
# judge.py (local machine)
from agentbeats.tool_provider import ToolProvider
from agentbeats.cloudflare import quick_tunnel

async def main():
    args = parse_args()

    if args.cloudflare_quick_tunnel:
        agent_url_cm = quick_tunnel(f"http://{args.host}:{args.port}")
    else:
        agent_url_cm = contextlib.nullcontext(f"http://{args.host}:{args.port}/")

    async with agent_url_cm as public_url:
        judge = DebateJudge()
        judge._tool_provider = ToolProvider()

        # Communicate with remote debaters via ToolProvider
        await run_debate(judge, {
            "pro_debater": "https://pro-abc123.trycloudflare.com",
            "con_debater": "https://con-xyz789.trycloudflare.com"
        })
```

**Both utilities working together:**
- **Cloudflare:** Makes judge accessible remotely
- **ToolProvider:** Judge communicates with remote debaters

### Example 3: Tool as ADK Function

**Scenario:** Expose talk_to_agent to Google ADK Agent

```python
# adk_debate_judge.py
from agentbeats.tool_provider import ToolProvider
from google.adk.agents import Agent
from google.adk.tools import FunctionTool

tool_provider = ToolProvider()

root_agent = Agent(
    name="debate_moderator",
    model="gemini-2.0-flash",
    system_instruction="You are a debate moderator...",
    tools=[
        # Expose as tool for LLM to use
        FunctionTool(tool_provider.talk_to_agent)
    ]
)

# LLM can now call: talk_to_agent(message="...", url="...", new_conversation=False)
```

---

## Best Practices

### ToolProvider Best Practices

#### 1. Always Reset After Evaluation

```python
async def run_eval(self, req: EvalRequest, updater: TaskUpdater):
    try:
        # ... evaluation logic ...
    finally:
        self._tool_provider.reset()  # ← Always clean up
```

**Why:** Prevents context leakage between evaluations.

#### 2. Choose Correct Conversation Mode

```python
# ✓ GOOD: Stateful when agent needs history
attacker_response = await tool_provider.talk_to_agent(
    "Learn from previous rounds",
    attacker_url,
    new_conversation=False
)

# ✓ GOOD: Stateless for independent evaluation
defender_response = await tool_provider.talk_to_agent(
    "Evaluate this attack",
    defender_url,
    new_conversation=True
)

# ✗ BAD: Using wrong mode
defender_response = await tool_provider.talk_to_agent(
    "Evaluate this attack",
    defender_url,
    new_conversation=False  # ← Defender shouldn't remember previous attacks
)
```

#### 3. Handle Errors Gracefully

```python
try:
    response = await tool_provider.talk_to_agent(message, url)
except RuntimeError as e:
    logger.error(f"Agent at {url} failed: {e}")
    # Decide: retry, skip, or fail evaluation?
    raise
```

#### 4. Consider Context Size

```python
# If conversation gets too long, consider resetting
if round_num % 5 == 0:  # Every 5 rounds
    tool_provider.reset()  # Start fresh to limit context
    # Re-establish necessary context
```

### Cloudflare Best Practices

#### 1. Make Tunnels Optional

```python
# ✓ GOOD: Tunnel is opt-in via CLI flag
if args.cloudflare_quick_tunnel:
    agent_url_cm = quick_tunnel(...)
else:
    agent_url_cm = contextlib.nullcontext(...)

# ✗ BAD: Always require tunnel
agent_url_cm = quick_tunnel(...)  # ← Forces cloudflared dependency
```

#### 2. Provide Fallback Options

```python
parser.add_argument("--cloudflare-quick-tunnel", action="store_true")
parser.add_argument("--card-url", help="Alternative: provide custom external URL")

if args.cloudflare_quick_tunnel:
    agent_url_cm = quick_tunnel(...)
elif args.card_url:
    agent_url_cm = contextlib.nullcontext(args.card_url)
else:
    agent_url_cm = contextlib.nullcontext(f"http://{args.host}:{args.port}/")
```

#### 3. Log Public URL Clearly

```python
async with quick_tunnel(...) as public_url:
    logger.info("=" * 60)
    logger.info(f"PUBLIC URL: {public_url}")
    logger.info(f"Local URL:  http://{args.host}:{args.port}")
    logger.info("=" * 60)
    await run_server()
```

**Why:** Makes it easy to find and share the URL.

#### 4. Document Requirements

```python
parser.add_argument(
    "--cloudflare-quick-tunnel",
    action="store_true",
    help=(
        "Use Cloudflare quick tunnel for public access. "
        "Requires: brew install cloudflared"
    )
)
```

#### 5. Handle Missing cloudflared

```python
if args.cloudflare_quick_tunnel:
    try:
        from agentbeats.cloudflare import quick_tunnel
        agent_url_cm = quick_tunnel(...)
    except FileNotFoundError:
        print("Error: cloudflared not found. Install with: brew install cloudflared")
        sys.exit(1)
```

---

## API Reference

### ToolProvider

```python
class ToolProvider:
    """Manages agent-to-agent communication with context tracking."""

    def __init__(self):
        """Initialize with empty context dictionary."""

    async def talk_to_agent(
        self,
        message: str,
        url: str,
        new_conversation: bool = False
    ) -> str:
        """
        Send message to agent and return response.

        Args:
            message: Text message to send
            url: Agent endpoint URL
            new_conversation: If True, reset context; if False, preserve

        Returns:
            Agent's text response

        Raises:
            RuntimeError: If agent returns non-completed status
            httpx.HTTPError: On network errors
            asyncio.TimeoutError: If request exceeds timeout (300s default)
        """

    def reset(self):
        """Clear all conversation contexts."""
```

### quick_tunnel

```python
@contextlib.asynccontextmanager
async def quick_tunnel(tunnel_url: str) -> AsyncIterator[str]:
    """
    Create temporary Cloudflare tunnel for local URL.

    Args:
        tunnel_url: Local URL to expose (e.g., "http://127.0.0.1:9010")

    Yields:
        Public HTTPS URL (e.g., "https://xyz.trycloudflare.com")

    Raises:
        FileNotFoundError: If cloudflared not installed
        asyncio.TimeoutError: If tunnel fails to establish

    Example:
        async with quick_tunnel("http://127.0.0.1:9010") as url:
            print(f"Public URL: {url}")
            await run_server()
        # Tunnel automatically closed
    """
```

---

## Troubleshooting

### ToolProvider Issues

**Problem:** Context not resetting between evaluations

```python
# Solution: Call reset() in finally block
try:
    await run_eval()
finally:
    self._tool_provider.reset()
```

**Problem:** Timeout errors with slow agents

```python
# Solution: Increase timeout in send_message
# Edit agentbeats/client.py:21
DEFAULT_TIMEOUT = 600  # Increase from 300
```

**Problem:** Agent returns failed status

```python
# Solution: Check agent logs for errors
# RuntimeError will include agent response
try:
    response = await tool_provider.talk_to_agent(...)
except RuntimeError as e:
    print(f"Agent failed: {e}")
    # Check agent's logs for root cause
```

### Cloudflare Issues

**Problem:** cloudflared not found

```bash
# Solution: Install cloudflared
brew install cloudflared  # macOS
apt install cloudflared    # Linux
```

**Problem:** Tunnel fails to establish

```bash
# Solution: Check internet connection and firewall
cloudflared tunnel --url http://127.0.0.1:9010
# Should see: "Your quick Tunnel has been created!"
```

**Problem:** 502 Bad Gateway errors

```python
# Solution: Ensure local server is running BEFORE creating tunnel
# Start server first, then tunnel
await uvicorn_server.serve()  # Server must be up
async with quick_tunnel(...):  # Then create tunnel
    ...
```

**Problem:** Random tunnel URLs inconvenient

```bash
# Solution: Use named tunnels for persistent URLs
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel agent.example.com
```

---

## Summary

Both `ToolProvider` and `cloudflare` are optional utility components that simplify common tasks in the AgentBeats framework:

- **ToolProvider:** Essential for orchestrators that need to communicate with multiple agents while managing conversation context
- **Cloudflare:** Optional feature for scenarios requiring public access or distributed testing

Choose the tools appropriate for your scenario's needs.
