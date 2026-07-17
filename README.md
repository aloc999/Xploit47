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
| Deterministic scoring | Same input → same score; explainable breakdown (no randomness) |
| Kill-chain phase | Auto-classifies recon → enum → vuln → exploit → privesc → post-ex |
| Tool recommendation | Auto-suggests tools (nmap, enum4linux, searchsploit, …) with confidence |
| Asset extraction | Pulls IP/hostname from step text when not provided |
| Path chaining | Auto-links sequential steps; returns full path + pathScore |
| Critical path | Auto-flags high-impact steps (CVE exploit, privesc, …) |
| Next-step hints | Phase-aware planning suggestions |
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
| `asset` | string | no | Target asset (auto-extracted if omitted) |
| `recommendedTool` | string | no | Tool (auto-recommended if omitted) |
| `critical` | boolean | no | Critical flag (auto-detected if omitted) |
| `parentId` | string | no | Explicit parent node (auto-links sequential steps) |

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
│   ├── reasoner.ts           # Strategy orchestration + auto parent links
│   ├── scoring.ts            # Deterministic score + kill-chain phase
│   ├── recommend.ts          # Tool / asset inference + next-step hints
│   ├── engine.ts             # Lightweight beam engine
│   ├── state.ts              # Node cache / path state
│   ├── types.ts              # Shared types & config
│   └── strategies/
│       ├── base.ts           # Shared evaluation + response builder
│       ├── beam-search.ts    # Beam Search
│       ├── mcts.ts           # Monte Carlo Tree Search
│       └── factory.ts        # Strategy factory
├── scripts/smoke-test.mjs    # Accuracy + MCP integration tests
├── tot-engine.js             # Standalone Tree-of-Thought helper
├── state-manager.js          # Standalone session helper
├── package.json
└── README.md
```

---

## License

MIT — see [LICENSE](./LICENSE).
