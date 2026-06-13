# SPL Guard

**Inline SPL governance for AI agents on Splunk MCP**

SPL Guard is an MCP-to-MCP reverse proxy that sits between your LangGraph agent
and the Splunk MCP Server. It intercepts every `tools/call` request, inspects
the SPL query, rewrites dangerous patterns before they reach Splunk, and records
every decision back into Splunk natively as an audit trail.

```
LangGraph Agent  ──►  SPL Guard Proxy (localhost:8080)  ──►  Splunk MCP Server
                         inspect · rewrite · log
```

**Three verdicts — all under 20ms:**

| Verdict | What happened | Example |
|---|---|---|
| SAFE | Forwarded unchanged | `index=main error earliest=-5m` |
| REWRITTEN | Unsafe bounds injected | `index=* earliest=-30d` → safe bounds |
| BLOCKED | Destructive command stopped | `index=main \| delete` |

---

## The problem it solves

When autonomous agents connect to Splunk via the MCP Server, they generate
non-deterministic SPL — wildcard index searches, unbounded time ranges — that
introduces search head concurrency risk and drives unintended SVC consumption.
With Splunk 10.4 Federated Search now generally available, a single unguarded
agent query can fan out across S3, Snowflake, and Azure Data Lake simultaneously.

Splunk's rate limiter drops requests. MCP Watch flags them post-execution.
Neither fixes them. SPL Guard fixes them at the edge before they execute.

---

## Prerequisites

- Windows 10 or Windows 11
- Python 3.11 (Anaconda recommended)
- Splunk Enterprise installed on Windows with MCP Server app v1.2
- Encrypted MCP token generated inside the Splunk MCP Server app
- Gemini API key (Google AI Studio)

---

## Quick start

**Step 1 — Open Command Prompt as Administrator**

Press Windows key → type `cmd` → right click → Run as administrator

**Step 2 — Set up environment**

```cmd
cd C:\Users\%USERNAME%\Hackathon\splunk_hackathon
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**Step 3 — Configure**

Copy the example config:
```cmd
copy .env.example .env
notepad .env
```

Fill in these values:

| Variable | Where to get it |
|---|---|
| `SPLUNK_MCP_ENDPOINT` | Splunk MCP Server app — copy the endpoint URL shown |
| `SPLUNK_MCP_ENCRYPTED_TOKEN` | Splunk MCP Server app → Generate Token (shown once — copy immediately) |
| `GEMINI_API_KEY` | Google AI Studio |
| `SPLGUARD_MODE` | `active` (default) / `passive` / `bypass` — see governance modes below |

Example `.env`:
```
SPLUNK_MCP_ENDPOINT=https://your-computer-name:8089/services/mcp
SPLUNK_MCP_ENCRYPTED_TOKEN=your_encrypted_token_here
GEMINI_API_KEY=your_gemini_key_here
PROXY_HOST=127.0.0.1
PROXY_PORT=8080
MEMORY_DB_PATH=./memory/query_cache.db
LANGCHAIN_TRACING_V2=false
```

**Important:** The encrypted MCP token is displayed only once.
Copy it before closing the token generation window.

**Step 4 — Create required `__init__.py` files**

```cmd
type nul > C:\Users\%USERNAME%\Hackathon\splunk_hackathon\proxy\__init__.py
type nul > C:\Users\%USERNAME%\Hackathon\splunk_hackathon\spl\__init__.py
type nul > C:\Users\%USERNAME%\Hackathon\splunk_hackathon\memory\__init__.py
type nul > C:\Users\%USERNAME%\Hackathon\splunk_hackathon\telemetry\__init__.py
type nul > C:\Users\%USERNAME%\Hackathon\splunk_hackathon\tests\__init__.py
```

**Step 5 — Run tests**

```cmd
set PYTHONPATH=C:\Users\%USERNAME%\Hackathon\splunk_hackathon
python -m pytest tests/ -v
```

All 23 tests should pass before running the proxy.

**Step 6 — Start the proxy**

```cmd
set PYTHONPATH=C:\Users\%USERNAME%\Hackathon\splunk_hackathon
uvicorn proxy.main:app --host 127.0.0.1 --port 8080 --reload
```

Verify in a second Command Prompt window:
```cmd
curl http://127.0.0.1:8080/health
```

Expected:
```json
{"status":"ok","target":"https://your-computer-name:8089/services/mcp"}
```

**Step 7 — Point your agent at the proxy**

Change your LangGraph MCP server URL from:
```
https://your-computer-name:8089/services/mcp
```
to:
```
http://127.0.0.1:8080/mcp
```

The agent sends standard MCP JSON-RPC — SPL Guard is completely transparent.

**Step 8 — Start the FinOps dashboard**

Open a third Command Prompt window:

```cmd
cd C:\Users\%USERNAME%\Hackathon\splunk_hackathon
set PYTHONPATH=C:\Users\%USERNAME%\Hackathon\splunk_hackathon
set PROXY_BASE_URL=http://127.0.0.1:8080
.venv\Scripts\activate
streamlit run telemetry/dashboard.py --server.port 8502
```

Opens automatically at `http://localhost:8502`

---

## Running the demo loop

Open PowerShell (separate from the proxy window) and run each query.

**Query 1 — Standard dangerous query (REWRITTEN):**

```powershell
$body = '{"jsonrpc":"2.0","id":"t1","method":"tools/call","params":{"name":"splunk_run_query","arguments":{"query":"index=* earliest=-30d status=404"}}}'
Invoke-WebRequest -Uri "http://127.0.0.1:8080/mcp" -Method POST -ContentType "application/json" -Body $body -UseBasicParsing | Select-Object -ExpandProperty Content
```

Expected proxy log:
```
REWRITTEN | reasons=['Wildcard index (index=*)', 'Time range exceeds 1 day'] | risk=high | 16ms
```

**Query 2 — Federated Search dangerous query (REWRITTEN):**

```powershell
$body = '{"jsonrpc":"2.0","id":"t2","method":"tools/call","params":{"name":"splunk_run_query","arguments":{"query":"search index=fed:* earliest=-30d error"}}}'
Invoke-WebRequest -Uri "http://127.0.0.1:8080/mcp" -Method POST -ContentType "application/json" -Body $body -UseBasicParsing | Select-Object -ExpandProperty Content
```

Expected proxy log:
```
REWRITTEN | reasons=['Federated wildcard — fans out across all remote environments'] | risk=high
```

**Query 3 — Destructive command (BLOCKED):**

```powershell
$body = '{"jsonrpc":"2.0","id":"t3","method":"tools/call","params":{"name":"splunk_run_query","arguments":{"query":"search index=main | delete"}}}'
Invoke-WebRequest -Uri "http://127.0.0.1:8080/mcp" -Method POST -ContentType "application/json" -Body $body -UseBasicParsing | Select-Object -ExpandProperty Content
```

Expected response — returned instantly, never reached Splunk:
```json
{"error":{"message":"Query blocked by SPL Guard","data":{"reasons":["delete command — destructive"]}}}
```

**Query 4 — Repeat Query 1 (CACHE HIT):**

Run Query 1 again. Expected proxy log:
```
CACHE HIT | hash=xxxxxxxx
```

Same bad pattern — served from memory, not re-inspected.

---

## Resetting for a clean demo

Delete the SQLite cache before recording your demo video so numbers
start from zero and build up live:

```cmd
del C:\Users\%USERNAME%\Hackathon\splunk_hackathon\memory\query_cache.db
```

Restart the proxy after deleting the cache.

---

## Splunk setup (Windows)

SPL Guard requires Splunk Enterprise on Windows with:

1. **Splunk MCP Server app** installed from Splunkbase
2. **Token authentication enabled:**
   ```
   Splunk Web → Settings → Tokens → Enable Token Authentication → ON
   ```
3. **`mcp_user` role created** with capabilities:
   ```
   mcp_tool_execute · edit_tokens_own · rest_apps_view · search
   ```
4. **Role assigned** to your Splunk admin user
5. **Encrypted token generated** inside the MCP Server app
   (not from Settings → Tokens — those tokens do not work for MCP)

Splunk Web runs at `http://localhost:8000` by default on Windows.
The MCP endpoint is at `https://your-computer-name:8089/services/mcp`.

---

## Governance modes

SPL Guard supports three operating modes controlled by  in :

| Mode | What it does | When to use |
|---|---|---|
|  | Intercept, rewrite, block — full governance | Production (default) |
|  | Observe and log only — forward everything unchanged | Evaluation before go-live |
|  | Completely transparent — no inspection at all | Emergency maintenance |

**Switching modes:**

1. Update  in 
2. Save the file — uvicorn auto-reloads
3. Dashboard mode indicator updates immediately

**Passive mode demo:**

Set  and restart the proxy. The dashboard turns yellow and proxy logs show  — you can see exactly what would have been changed without affecting any queries. Switch back to  when ready.

---

## Project structure

```
splguard/
├── .env.example                   # configuration template — copy to .env
├── requirements.txt               # pip install -r this
├── README.md                      # this file
├── LICENSE                        # MIT
├── proxy/
│   ├── __init__.py
│   ├── main.py                    # Layer 1 — FastAPI MCP-to-MCP proxy
│   └── splunk_mcp_client.py       # all Splunk communication — one token, one channel
├── spl/
│   ├── __init__.py
│   └── inspector.py               # Layer 2 — deterministic SPL inspector + rewriter
├── memory/
│   ├── __init__.py
│   └── query_cache.py             # Layer 3 — SQLite rewrite cache
├── telemetry/
│   ├── __init__.py
│   └── dashboard.py               # Layer 5 — Streamlit FinOps dashboard
└── tests/
    ├── __init__.py
    └── test_spl_inspector.py      # 23 tests — run before demo
```

---

## SPL patterns detected

| Pattern | Verdict | Risk |
|---|---|---|
| `index=*` wildcard | REWRITTEN | High |
| `earliest=-30d` or wider | REWRITTEN | High |
| `alltime` keyword | REWRITTEN | High |
| `index=fed:*` federated wildcard | REWRITTEN | High |
| `index=fed:X earliest=-30d` | REWRITTEN | High |
| SPL2 federated with wide time range | REWRITTEN | High |
| Missing index or time bounds | REWRITTEN | Medium |
| `\| delete` command | BLOCKED | — |
| `\| rest` bypass | BLOCKED | — |
| Subsearch injection (CVE-2025-20381) | BLOCKED | — |
| Delete on federated index | BLOCKED | — |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  LangGraph Agent                                     │
│  Generates raw SPL via tools/call                   │
└──────────────────────┬──────────────────────────────┘
                       │ MCP JSON-RPC
                       ▼
┌─────────────────────────────────────────────────────┐
│  SPL Guard Proxy  (Layer 1 — FastAPI)               │
│  Windows · localhost:8080                           │
│                                                      │
│  ┌─────────────────────────────────────────────┐    │
│  │  SPL Intelligence Engine  (Layer 2)         │    │
│  │  Deterministic regex · <20ms · no LLM      │    │
│  │  SAFE / REWRITTEN / BLOCKED                │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ┌─────────────────────────────────────────────┐    │
│  │  Query Memory Cache  (Layer 3)              │    │
│  │  SQLite · SHA-256 keyed · learns per session│    │
│  └─────────────────────────────────────────────┘    │
└──────────────────────┬──────────────────────────────┘
                       │ encrypted MCP token
                       │ one channel · no side connections
                       ▼
┌─────────────────────────────────────────────────────┐
│  Splunk Enterprise  (Windows · port 8089)           │
│  MCP Server v1.2                                    │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐                 │
│  │ _internal    │  │ splguard_    │                 │
│  │ telemetry    │  │ audit index  │                 │
│  └──────────────┘  └──────────────┘                 │
└─────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  FinOps Dashboard  (Layer 5 — Streamlit)            │
│  Windows · localhost:8502                           │
│  SVC units saved · $ saved · cache hit rate        │
│  Source: Splunk _internal via MCP channel          │
└─────────────────────────────────────────────────────┘
```

---

## Technology stack

Python 3.11 · FastAPI · uvicorn · httpx · Pydantic v2 ·
LangGraph · LangChain · Gemini 2.0 Flash · Streamlit ·
SQLite · OpenTelemetry · Splunk Enterprise (Windows) ·
Splunk MCP Server v1.2

---

## License

MIT — see LICENSE file.