# Xploit47

**Systematic, AI-powered penetration testing reasoning engine (MCP server)** for attack path planning, CTF/HTB solving, and authorized pentest workflows.

Features **Beam Search**, **Monte Carlo Tree Search (MCTS)**, attack step scoring, tool recommendations, and critical-path highlighting.

---

## What is Xploit47?

Xploit47 is a **Model Context Protocol (MCP)** server that turns an LLM into a structured, methodical pentest planner and advisor. It does **not** run exploits against targets — it reasons about attack chains, scores steps, and recommends next actions and tools.

| Capability | Description |
|---|---|
| Beam Search | Fixed-width exploration of the most promising attack paths |
| MCTS | Simulation-based exploration for uncertain / complex scenarios |
| Step scoring | Likelihood, impact heuristics, chain coherence |
| Tool hints | Suggests tools (nmap, enum4linux, searchsploit, etc.) via your client |
| Critical path | Highlights highest-value steps in the chain |
| MCP-native | Works with Claude Desktop, Cursor, Grok, and other MCP clients |

---

## How it works

1. **Input** — You (or your AI) provide the current attack step/state  
   e.g. `"Enumerate SMB on 10.10.10.10"`
2. **Reasoning** — Xploit47 uses Beam Search or MCTS to score and track the path
3. **Output** — Returns step metadata, score, strategy used, and tree statistics

### Example HTB-style workflow

| # | Input step | Suggested direction | Tool |
|---|---|---|---|
| 1 | Start recon on target | Full port scan | nmap |
| 2 | nmap complete | Enumerate SMB on 445 | enum4linux |
| 3 | SMB enum done | Search public SMB CVEs | searchsploit |
| 4 | CVE found | Authorized exploit path | metasploit |
| 5 | Shell as user | Priv-esc enumeration | winPEAS / linpeas |
| 6 | Need root | Check common misconfigs | manual |

---

## Installation

```bash
git clone https://github.com/aloc999/Xploit47.git
cd Xploit47
npm install
npm run build
```

Requirements: **Node.js ≥ 18**

---

## Usage (MCP client config)

Add to your MCP client (Claude Desktop, Cursor, Grok, etc.):

```json
{
  "mcpServers": {
    "Xploit47": {
      "command": "node",
      "args": ["/absolute/path/to/Xploit47/dist/index.js"]
    }
  }
}
```

Or run directly:

```bash
npm start
# equivalent: node dist/index.js
```

### Tool: `xploit47`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `attackStep` | string | yes | Current attack step description |
| `attackStepNumber` | integer ≥ 1 | yes | Current step number |
| `totalAttackSteps` | integer ≥ 1 | yes | Estimated total steps |
| `nextAttackStepNeeded` | boolean | yes | Whether another step is needed |
| `strategyType` | `"beam_search"` \| `"mcts"` | no | Search strategy (default: beam_search) |
| `asset` | string | no | Target asset label |
| `recommendedTool` | string | no | Suggested tool for this step |
| `critical` | boolean | no | Mark as critical path |

---

## Search strategies

### Beam Search (`beam_search`)

- Keeps a fixed-width set of the best attack paths
- Best for methodical exploit chaining and known patterns
- Use for: enumeration sequences, CVE chaining, linear CTF paths

### Monte Carlo Tree Search (`mcts`)

- Simulation-based exploration with UCB1 selection
- Balances exploring new vectors vs exploiting known weaknesses
- Use for: complex networks, uncertain outcomes, multi-stage APT-style planning

---

## Ethics & legal

Xploit47 is a **reasoning / planning** tool only. Use it only on systems you are **authorized** to test (your own labs, CTF platforms, or programs with written permission / safe harbor). Unauthorized access is illegal.

---

## Development

```bash
npm run dev      # tsx src/index.ts
npm run build    # tsc → dist/
npm start        # node dist/index.js
```

### Project layout

```
Xploit47/
├── src/
│   ├── index.ts              # MCP server entry (stdio)
│   ├── reasoner.ts           # Strategy orchestration
│   ├── engine.ts             # Lightweight beam engine
│   ├── state.ts              # Node cache / path state
│   ├── types.ts              # Shared types & config
│   └── strategies/
│       ├── base.ts           # Shared scoring
│       ├── beam-search.ts    # Beam Search
│       ├── mcts.ts           # Monte Carlo Tree Search
│       └── factory.ts        # Strategy factory
├── tot-engine.js             # Standalone Tree-of-Thought helper
├── state-manager.js          # Standalone session helper
├── package.json
└── README.md
```

---

## License

MIT — see [LICENSE](./LICENSE).
