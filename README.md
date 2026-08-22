# Dummy_Hackathon
# AI Agentic Hackathon

An Agentic AI application developed as part of the AI Agentic Hackathon.

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
* Streamlit
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

# 18. Streamlit UI

After the backend agent is functional, a Streamlit interface will be added.

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
[ ] Streamlit
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
Streamlit
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
