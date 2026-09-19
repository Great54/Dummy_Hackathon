# Dummy_Hackathon
# AI Agentic Hackathon

An Agentic AI application developed as part of the AI Agentic Hackathon.

---

## Log Analyzer (Native Desktop App)

**Log Analyzer** is a native Windows desktop application built with **PySide6** for
analyzing software and communication defects using a local repository plus
optional BLF, MF4, PCAPNG and TTL log/config files. It runs as a normal desktop
window — there is no browser, no local web server, and no Streamlit involved.

### Run in development

```bash
pip install -r requirements.txt
python main.py
```

### Optional Local Deep Analysis

Gemini 3.6 Flash remains the default structured reasoning provider. For local,
private analysis without cloud API-token usage, install Ollama separately and
pull a coding/reasoning model such as Qwen Coder:

```powershell
ollama pull qwen2.5-coder:14b
```

Select it in `.env`:

```text
LLM_PROVIDER=ollama
OLLAMA_MODEL=qwen2.5-coder:14b
OLLAMA_HOST=http://127.0.0.1:11434
```

Use `LLM_PROVIDER=gemini` (or omit it) to retain Gemini. Ollama runs locally;
model download size, RAM, GPU VRAM, and response speed depend on the selected
model and workstation. The same bounded evidence is sent to either provider.

### Package as a standalone executable

```bash
pyinstaller --onedir --name LogAnalyzer main.py
```

The generated executable is created at `dist/LogAnalyzer/LogAnalyzer.exe` and
launches the native PySide6 window directly.

### Architecture

```text
PySide6 UI (app/gui.py)
    |
    v
Input Handler (input/handler.py)
    |
    v
AnalysisRequest (input/models.py)
    |
    v
Analysis / Agent backend (app/agent.py, app/log_anaylzer.py, app/llm_summary.py)
```

Long-running analysis work runs on a `QThread` (`app/worker.py`) so the UI
never freezes.

### Repository investigation

Repository analysis runs after applicable log tools and derives at most 12
search targets from the defect and existing evidence. It performs one bounded,
case-insensitive pass over safe text files and returns relative paths, line
numbers, and short redacted contexts only.

Default limits are 5,000 files, 10 MiB per file, 30 matches across 20 files,
three context lines on either side, and 2,000 context characters. Build,
dependency, cache, VCS, credential, environment, certificate, and private-key
paths are ignored. Resolved paths and symlinks may not escape the selected
repository root. Repository files are never executed or modified.

### BLF analysis dependency

The BLF tool uses `vblf` 0.3.1 (MIT license) for incremental access to CAN,
CAN-FD, and supported Ethernet BLF objects. Ethernet/IP/SOME-IP headers are
decoded locally with bounded parsers; raw log files and complete payloads are
never sent to Gemini. `python-can` was evaluated but its BLF reader only emits
CAN/CAN-FD objects, while Scapy was not selected because its GPL-2.0-only
license and broad packet stack are unnecessary for this use case.

### TTTech TTL trace analysis

Binary TTTech TTX Logger files (`TTL ` magic) are decoded by a separately
installed TShark executable. The application does not bundle or redistribute
Wireshark. Set `TSHARK_PATH` in `.env` when `tshark` is not on `PATH`; on Windows,
the registered Wireshark installation is also discovered automatically.

```text
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
TTL_TSHARK_PACKET_LIMIT=100000
TTL_TSHARK_TIMEOUT_SECONDS=300
```

The default analysis is intentionally limited to the first 100,000 decoded
records. TShark output is streamed, only selected fields are requested, and no
converted capture is created. Wireshark/TShark is GPL-2.0-or-later; review its
license separately before distributing it with this application.

The project will evolve from a basic Gemini LLM application into a tool-using AI agent capable of reasoning, selecting tools, retrieving information, executing tasks, and producing a final response.

---

## 1. Project Goal

The goal of this project is to build an AI agent that can:

* Understand a user's request
* Decide what actions are required
* Select appropriate tools
* Retrieve information from internal documents
* Perform calculations or other operations
* Use external APIs when required
* Combine results from multiple tools
* Produce a final response

The target architecture is:

```text
                         USER
                           |
                           v
                    +--------------+
                    |  AI AGENT    |
                    |    GEMINI    |
                    +------+-------+
                           |
                    What should I do?
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
         RAG Tool     Calculator      API Tool
             |             |             |
             v             v             v
          FAISS         Python       External API
             |             |             |
             +-------------+-------------+
                           |
                           v
                     Tool Results
                           |
                           v
                    +--------------+
                    |    GEMINI    |
                    +------+-------+
                           |
                           v
                     FINAL ANSWER
```

---

# 2. Technology Stack

Current technology stack:

* Python
* Google Gemini API
* `google-genai` Python SDK
* Python virtual environment (`venv`)
* GitHub
* GitHub Codespaces
* VS Code

Planned technologies:

* LangChain
* LangGraph
* FAISS
* RAG
* PySide6
* Tool / Function Calling
* External APIs
* Agent memory

---

# 3. Development Environment

The project is developed using:

```text
GitHub
   |
   v
GitHub Codespaces
   |
   v
VS Code
   |
   v
Python Virtual Environment
```

This allows the complete development environment to run inside the GitHub Codespace.

---

# 4. Repository Structure

The initial repository structure is:

```text
Dummy_Hackathon/
|
+-- app/
|   +-- agent.py
|
+-- data/
|   +-- documents/
|
+-- tests/
|
+-- venv/
|
+-- .env
+-- .gitignore
+-- requirements.txt
+-- README.md
+-- main.py
```

### Important

The following files/folders are local only and must NOT be pushed to GitHub:

```text
.env
venv/
```

The `.env` file contains secret API credentials.

The `venv/` directory contains the local Python environment.

---

# 5. Create the Python Virtual Environment

If a virtual environment does not already exist:

```bash
python -m venv venv
```

Activate it in GitHub Codespaces:

```bash
source venv/bin/activate
```

Verify:

```bash
which python
```

Expected result should point to something similar to:

```text
/workspaces/Dummy_Hackathon/venv/bin/python
```

Also verify Python:

```bash
python --version
```

---

# 6. Install Gemini SDK

With the virtual environment activated:

```bash
pip install google-genai python-dotenv
```

Google recommends the `google-genai` Python SDK for Gemini API development.

Save the installed dependencies:

```bash
pip freeze > requirements.txt
```

---

# 7. Gemini API Key

Create a Gemini API key using Google AI Studio.

The Gemini API requires an API key for authentication. Google AI Studio can create a project and API key for new users.

Create a file named:

```text
.env
```

in the root of the repository.

Add:

```text
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

Example:

```text
GEMINI_API_KEY=AIzaSyXXXXXXXXXXXX
```

Never commit this file to GitHub.

---

# 8. Git Ignore Configuration

Create:

```text
.gitignore
```

in the root of the repository.

Add:

```text
.env
venv/
__pycache__/
*.pyc
```

This prevents Git from tracking:

* Gemini API keys
* Python virtual environments
* Python cache files

Verify:

```bash
git status
```

`.env` and `venv/` should not appear as files to commit.

---

# 9. First Gemini API Test

Create:

```text
app/agent.py
```

Initial implementation:

```python
import os

from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY is not set")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model="gemini-3.6-flash",
    contents="Explain agentic AI in simple terms."
)

print(response.text)
```

Run:

```bash
python app/agent.py
```

Expected flow:

```text
Python
   |
   v
.env
   |
   v
Gemini API
   |
   v
Gemini 3.6 Flash
   |
   v
Response
```

The current Gemini model documentation lists `gemini-3.6-flash` as a stable model.

---

# 10. Current Milestone

## Milestone 1 — Gemini Connection

Status:

```text
[✓] GitHub repository created
[✓] GitHub Codespace configured
[✓] Python virtual environment created
[✓] Gemini SDK installed
[✓] python-dotenv installed
[✓] .env created
[✓] .gitignore created
[ ] Gemini API tested
[ ] First response received
```

The next objective is to successfully receive a response from Gemini.

---

# 11. From LLM to Agent

The first implementation is NOT yet an agent.

Currently:

```text
User
 |
 v
Gemini
 |
 v
Answer
```

This is a basic LLM application.

The goal is to introduce tools:

```text
User
 |
 v
Gemini Agent
 |
 +----> Tool 1
 |
 +----> Tool 2
 |
 +----> Tool 3
 |
 v
Tool Results
 |
 v
Gemini
 |
 v
Final Answer
```

The agent should be able to decide when a tool is required.

---

# 12. Planned Tools

The first tools planned for the agent are:

### Tool 1 — Document Search

Search internal documents using RAG.

```text
User Question
     |
     v
Agent
     |
     v
Document Search Tool
     |
     v
FAISS
     |
     v
Relevant Documents
     |
     v
Agent
```

### Tool 2 — Calculator

Perform mathematical calculations when required.

```text
Agent
 |
 v
Calculator Tool
 |
 v
Calculation Result
 |
 v
Agent
```

### Tool 3 — External API

Allow the agent to retrieve information from an external API.

```text
Agent
 |
 v
API Tool
 |
 v
External Service
 |
 v
Result
 |
 v
Agent
```

---

# 13. RAG Integration

Existing RAG learning material will be used as the foundation for the document-search capability.

Instead of building a standalone RAG chatbot:

```text
Question
 |
 v
RAG
 |
 v
Answer
```

RAG will become a tool available to the agent:

```text
                 Agent
                   |
            Need documents?
                   |
                  YES
                   |
                   v
             RAG Tool
                   |
                   v
                FAISS
                   |
                   v
              Documents
                   |
                   v
                 Agent
```

This allows the agent to decide whether internal knowledge is required.

---

# 14. Multi-Tool Agent

The target initial agent will have multiple tools:

```text
                    GEMINI AGENT
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       RAG Tool      Calculator      API Tool
          |              |              |
          v              v              v
        FAISS          Python       External API
          |              |              |
          +--------------+--------------+
                         |
                         v
                    Tool Results
                         |
                         v
                       Gemini
                         |
                         v
                    Final Answer
```

---

# 15. Example Agent Workflow

Example user request:

```text
Search the internal documentation for product information,
calculate the total cost for 5 units, and recommend the best option.
```

The agent should reason approximately like:

```text
1. Understand user request

2. Need product information
       |
       v
   Call RAG Tool

3. Receive product information

4. Need cost calculation
       |
       v
   Call Calculator Tool

5. Receive calculation result

6. Compare available options

7. Generate recommendation

8. Return final answer
```

This demonstrates actual agentic behavior.

---

# 16. LangChain Integration

LangChain can be introduced once the basic Gemini API connection works.

Planned architecture:

```text
Python Application
       |
       v
LangChain
       |
       v
Gemini
       |
       +---- Tools
       |
       +---- RAG
       |
       +---- Memory
```

Install when required:

```bash
pip install langchain langchain-core
```

---

# 17. LangGraph Integration

LangGraph will be introduced after the basic tool-calling agent is working.

The purpose is to manage:

* Agent state
* Tool execution
* Multi-step workflows
* Conditional routing
* Retry logic
* Memory
* Planning

Target workflow:

```text
                    USER
                      |
                      v
                  PLANNER
                      |
                      v
                    GEMINI
                      |
              +-------+-------+
              |       |       |
              v       v       v
             RAG   Calculator  API
              |       |       |
              +-------+-------+
                      |
                      v
                 Observation
                      |
                      v
                   GEMINI
                      |
                More tools?
                  /     \
                YES      NO
                 |        |
                 +--------+
                      |
                      v
                FINAL ANSWER
```

---

# 18. PySide6 Desktop UI

The backend agent is exposed through a native PySide6 desktop interface
(`app/gui.py`), launched via `python main.py`.

Target UI:

```text
+---------------------------------------+
|          AI AGENTIC ASSISTANT         |
+---------------------------------------+
|                                       |
| User: Search our documentation...     |
|                                       |
| Agent:                                |
| ✓ Understanding request               |
| ✓ Searching documents                 |
| ✓ Calculating result                  |
| ✓ Comparing options                   |
|                                       |
| Final Answer:                         |
| ...                                   |
|                                       |
+---------------------------------------+
```

The UI should make the agent's tool usage visible during the hackathon demonstration.

---

# 19. Development Roadmap

### Phase 1 — Environment

```text
[✓] GitHub repository
[✓] GitHub Codespace
[✓] Python venv
[✓] .env
[✓] .gitignore
[✓] Gemini SDK
```

### Phase 2 — Gemini

```text
[ ] Gemini API connection
[ ] Basic prompt
[ ] Gemini response
```

### Phase 3 — Agent

```text
[ ] Tool definition
[ ] Function calling
[ ] Calculator tool
[ ] Agent decides when to use calculator
```

### Phase 4 — RAG

```text
[ ] Document ingestion
[ ] Embeddings
[ ] FAISS vector store
[ ] Retriever
[ ] RAG as agent tool
```

### Phase 5 — Multiple Tools

```text
[ ] Calculator
[ ] RAG
[ ] External API
[ ] Tool selection
[ ] Multi-step execution
```

### Phase 6 — Agent Workflow

```text
[ ] LangGraph
[ ] Agent state
[ ] Planning
[ ] Conditional routing
[ ] Retry handling
```

### Phase 7 — UI

```text
[x] PySide6 desktop window
[ ] Chat interface
[ ] Tool execution display
[ ] Final response display
```

### Phase 8 — Hackathon Demo

```text
[ ] Real-world use case
[ ] End-to-end scenario
[ ] Error handling
[ ] Logging
[ ] README documentation
[ ] Architecture diagram
[ ] Demo preparation
```

---

# 20. Git Workflow

Before committing:

```bash
git status
```

Add changes:

```bash
git add .
```

Commit:

```bash
git commit -m "Initial Gemini agent setup"
```

Push:

```bash
git push origin main
```

Check the current branch if required:

```bash
git branch --show-current
```

---

# 21. Security

Never commit:

```text
.env
```

Never hard-code:

```python
api_key = "AIzaSy..."
```

Use:

```python
import os

api_key = os.getenv("GEMINI_API_KEY")
```

API keys should remain in environment variables.

---

# 22. Current Project Philosophy

The project will be developed incrementally.

We will NOT start with a complicated multi-agent architecture.

Development sequence:

```text
Gemini
  ↓
Gemini + Tool
  ↓
Gemini + Multiple Tools
  ↓
Gemini + RAG
  ↓
Multi-step Agent
  ↓
LangGraph
  ↓
PySide6 Desktop UI
  ↓
Hackathon Demo
```

The objective is to have a working system at every stage rather than building the complete architecture at once.

---

# 23. Useful References

Google Gemini API documentation:

https://ai.google.dev/gemini-api/docs

Gemini models:

https://ai.google.dev/gemini-api/docs/models

Google AI Studio:

https://aistudio.google.com/

The Gemini API currently provides a free tier for selected models and usage, subject to Google's current rate limits and pricing policies. Check the official pricing page before relying on free-tier limits for the hackathon.
