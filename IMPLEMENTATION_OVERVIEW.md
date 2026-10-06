# Repository Implementation Overview

## 1. Purpose

This repository implements a native Windows desktop application for investigating
automotive software and communication defects. A user supplies:

- a source-code repository,
- a defect description,
- and optional BLF, TTL, MF4, or PCAPNG files.

The application runs the applicable local analysis tools, converts their findings
into bounded structured evidence, and asks either Gemini or a local Ollama model to
produce a root-cause assessment, recommendations, hypotheses, and next investigation
steps.

The main implemented product is the PySide6 desktop application. `app/agent.py` is a
separate, older Gemini command-line demo and is not part of the desktop analysis
pipeline.

## 2. High-Level Architecture

```text
User
  |
  v
PySide6 GUI (app/gui.py)
  |
  v
Input validation (input/handler.py)
  |
  v
AnalysisRequest (input/models.py)
  |
  v
AnalysisOrchestrator (app/orchestrator/orchestrator.py)
  |
  +-- BLF analysis
  +-- TTTech binary TTL trace analysis
  +-- RDF Turtle TTL analysis
  +-- bounded repository investigation
  +-- local hybrid repository RAG
  |
  v
Structured Evidence (app/orchestrator/evidence.py)
  |
  v
ReasoningAgent (app/agent/reasoning_agent.py)
  |
  +-- Gemini, by default
  +-- Ollama, when configured
  |
  v
AnalysisResult rendered in the GUI
```

Long-running validation and analysis execute on `QThread` workers, keeping the UI
responsive while progress messages and cancellation requests travel between the GUI,
orchestrator, and tools.

## 3. Entry Points

### Desktop application

The supported entry point is root-level `main.py`:

```powershell
python main.py
```

It adds the project root to `sys.path`, imports `app.gui.run`, creates the Qt
application, and opens `LogAnalyzerWindow`. There is no browser, web server, or
Streamlit runtime.

`app/main.py` is another small launcher for the same GUI.

### Standalone Gemini demo

`app/agent.py` loads `GEMINI_API_KEY`, creates a Gemini client, and starts a terminal
chat loop. It does not use the orchestrator, analysis tools, evidence models, or the
desktop result view.

## 4. End-to-End Analysis Flow

1. The user selects a repository and optional log files in `LogAnalyzerWindow`.
2. The user enters a non-empty defect description.
3. `input.handler.create_analysis_request` validates paths and creates an
   `AnalysisRequest`.
4. `AnalysisOrchestrator.run` asks the registry for applicable tools.
5. Tools execute sequentially in ascending phase order and may receive evidence from
  earlier tools. Repository RAG therefore receives log and deterministic repository
  evidence before retrieval.
6. Every tool returns one `Evidence` object. A tool failure is captured as error
   evidence so other tools can continue.
7. `ReasoningAgent.analyze` serializes the defect and bounded evidence into a prompt.
8. The configured LLM returns structured JSON.
9. The agent parses and validates the response into an `AnalysisResult`.
10. The GUI displays root cause, confidence, evidence, recommendations, hypotheses,
    and next investigation steps.

The current orchestration is deterministic and phase-based. The LLM does not choose
which tool to run next.

## 5. Input Model and Validation

`input/models.py` defines `AnalysisRequest` with these fields:

| Field | Required | Purpose |
| --- | --- | --- |
| `repo_path` | Yes | Repository to investigate |
| `defect_description` | Yes | Problem statement and search context |
| `blf_path` | No | Vector BLF trace |
| `mf4_path` | No | MDF/MF4 trace placeholder |
| `pcapng_path` | No | PCAPNG trace placeholder |
| `ttl_path` | No | TTTech binary TTL or RDF Turtle file |

`input/handler.py` verifies that required values are present, the repository is a
directory, and selected files exist with acceptable extensions. Validation checks
metadata and paths; it does not parse logs.

## 6. Tool Framework

`app/tools/base.py` defines the `AnalysisTool` contract:

- `name` identifies the tool in status and evidence output.
- `phase` controls execution order.
- `is_applicable(request)` decides whether the tool should run.
- `run(request, on_progress, prior_evidence)` produces one bounded `Evidence`.

`app/tools/registry.py` currently registers:

1. `BlfTool`
2. `TtlTraceTool`
3. `TtlTool`
4. `RepositoryTool`
5. `RagRepositoryTool`

The registry can accept additional tools through `register_tool` without changing the
orchestrator.

### 6.1 BLF analysis

`app/tools/blf_tool.py` uses `vblf` to incrementally inspect Vector BLF files. It
collects bounded statistics and examples rather than loading or returning the full
trace.

Implemented analysis includes:

- CAN and CAN-FD message counts,
- error counts, channels, time range, and duration,
- top CAN identifiers and bounded frame examples,
- Ethernet frame and protocol distributions,
- SOME/IP service, method, message-type, and return-code details,
- SOME/IP Service Discovery entries,
- BLF object-type frequencies.

Local protocol helpers under `app/tools/protocols/` decode Ethernet, IPv4, IPv6, UDP,
TCP, SOME/IP, and SOME/IP-SD structures.

### 6.2 TTTech binary TTL trace analysis

`app/tools/ttl_trace_tool.py` handles TTTech TTX Logger files identified by their
binary TTL signature. It:

- discovers TShark through `TSHARK_PATH` or the Windows Wireshark installation,
- invokes TShark with a fixed set of requested fields,
- streams CSV output instead of retaining complete packet output,
- summarizes CAN, Ethernet, IP, transport, SOME/IP, and SOME/IP-SD traffic,
- enforces a packet limit and timeout,
- terminates the subprocess when analysis is cancelled.

TShark/Wireshark is an external prerequisite and is not bundled by this repository.

### 6.3 RDF Turtle TTL analysis

`app/tools/ttl_tool.py` handles text-based RDF Turtle files. It extracts:

- prefixes and namespaces,
- service, message, signal, network, datatype, and relationship definitions,
- bounded examples for each category,
- defect-relevant lines scored from terms in the defect description.

The tool uses an incremental, regex-based scan. It is not a complete RDF semantic
reasoner.

### 6.4 Repository investigation

`app/tools/repository_tool.py` performs a deterministic, case-insensitive search over
safe text files in the selected repository. Search targets come from the defect
description and prior evidence.

Implemented safeguards and limits include:

- at most 5,000 files considered,
- files larger than 10 MiB skipped,
- at most 12 derived search targets,
- at most 30 matches across 20 files,
- three context lines and at most 2,000 context characters per match,
- build, dependency, cache, VCS, virtual-environment, and secret paths ignored,
- likely credentials redacted from returned context,
- resolved paths and symlinks prevented from escaping the repository root,
- repository files never executed or modified.

The resulting evidence can contain relative paths, line numbers, and short redacted
source snippets.

### 6.5 Hybrid repository RAG

`app/tools/rag_repository_tool.py` runs after deterministic repository search. The
components under `app/rag/` implement:

- line-aware 80-line chunks with 15-line overlap and an 8,000-character cap,
- local `sentence-transformers/all-MiniLM-L6-v2` embeddings,
- cosine-similarity retrieval through a local FAISS index,
- exact-identifier and deterministic keyword-result boosts,
- chunk deduplication and per-file diversity,
- a maximum of 8 chunks and 30,000 source characters per result,
- repository fingerprints based on relative path, size, and modification time,
- persistent repository-specific caches under `.cache/rag/`,
- atomic cache replacement and safe rebuild after changes or corruption.

The RAG tool uses the same file discovery, binary detection, ignored paths, size
limits, symlink boundaries, and redaction rules as `RepositoryTool`. It sends neither
embeddings nor the FAISS index to the reasoning provider. If indexing or retrieval
fails, it returns warning evidence and deterministic repository evidence remains
available.

## 7. Orchestration, Evidence, and Results

`app/orchestrator/orchestrator.py` owns one analysis run. It selects applicable tools,
sorts them by phase, reports progress, catches individual tool failures, and finally
invokes the reasoning agent.

`app/orchestrator/evidence.py` defines two serializable dataclasses:

- `Evidence`: source, summary, details, and severity.
- `AnalysisResult`: root cause, recommendation, evidence, raw model response,
  confidence, hypotheses, and next investigation steps.

If a tool raises an unexpected exception, the orchestrator logs it and adds an error
`Evidence` rather than discarding evidence from successful tools.

## 8. LLM Reasoning

`app/agent/reasoning_agent.py` builds a prompt from the defect, selected input names,
and tool evidence. Evidence included in the prompt is capped at approximately 60,000
characters.

The model is instructed to:

- reason only from supplied evidence,
- separate confirmed facts from hypotheses,
- return a defined JSON structure,
- provide confidence and practical next steps.

The parser accepts plain or Markdown-fenced JSON and converts it into an
`AnalysisResult`. If all available evidence is non-substantive or failed, the result
is marked as insufficient evidence instead of presenting an invented diagnosis.

### Gemini provider

`app/agent/gemini_client.py` uses the `google-genai` SDK. Gemini is the default
provider and requires `GEMINI_API_KEY`. `GEMINI_MODEL` can override the configured
model.

### Ollama provider

`app/agent/ollama_client.py` calls Ollama's local `/api/generate` endpoint with the
Python standard library. It supports `OLLAMA_HOST` and `OLLAMA_MODEL` and does not
require a cloud API key.

`app/agent/provider.py` selects the provider from `LLM_PROVIDER`, accepting only
`gemini` or `ollama`.

## 9. GUI and Background Work

`app/gui.py` implements the desktop workflow:

- repository and log file selection,
- defect-description entry,
- validation and analysis controls,
- progress and status output,
- cancellation,
- structured result rendering.

`app/worker.py` wraps callables in `AnalysisWorker`, a `QThread`. It emits progress,
success, and failure signals and forwards cancellation to targets that expose a
`cancel` method. Validation and full analysis use separate workers.

The orchestrator uses a `threading.Event` for cancellation. Long-running tools also
implement their own cancellation checks; the binary TTL tool can terminate TShark.

## 10. Configuration

Configuration is loaded from environment variables and `.env`:

```text
GEMINI_API_KEY=<key>
LLM_PROVIDER=gemini
GEMINI_MODEL=<model name>

OLLAMA_HOST=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5-coder:14b

TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
TTL_TSHARK_PACKET_LIMIT=100000
TTL_TSHARK_TIMEOUT_SECONDS=300
```

For local reasoning, set `LLM_PROVIDER=ollama`, install Ollama separately, and pull
the configured model. For Gemini, provide a valid API key.

## 11. Dependencies and Setup

Declared Python dependencies in `requirements.txt` are:

- `PySide6` for the native GUI,
- `google-genai` for Gemini,
- `python-dotenv` for `.env` loading,
- `vblf==0.3.1` for BLF access.
- `faiss-cpu` for the local vector index,
- `sentence-transformers` for local repository embeddings.

Development setup:

```powershell
py -3.11 -m venv venv311
.\venv311\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Optional external programs are Ollama for local LLM inference and TShark/Wireshark
for binary TTTech TTL analysis.

## 12. Tests

The `tests/` directory contains focused tests for:

| Test module | Main coverage |
| --- | --- |
| `test_blf_tool.py` | BLF parsing, bounding, CAN and Ethernet evidence |
| `test_gui_results.py` | Structured result rendering |
| `test_llm_provider.py` | Provider selection and provider behavior |
| `test_orchestrator_blf.py` | Tool discovery and evidence flow |
| `test_protocol_parsers.py` | Ethernet, SOME/IP, and SOME/IP-SD parsing |
| `test_rag_index.py` | Chunking, safety reuse, FAISS cache, reload and invalidation |
| `test_rag_retriever.py` | Exact, semantic, hybrid, bounded and diverse retrieval |
| `test_rag_repository_tool.py` | Evidence flow, fallback, cancellation and orchestration |
| `test_reasoning_agent.py` | Prompt and structured response handling |
| `test_repository_tool.py` | Search bounds, path safety, and redaction |
| `test_ttl_tool.py` | RDF Turtle extraction and relevance matching |
| `test_ttl_trace_tool.py` | TShark parsing, limits, errors, and cancellation |

Tests use `unittest`, temporary files, real bounded BLF serialization where useful,
and mocks for external systems such as Gemini, Ollama, and TShark.

Run the suite with:

```powershell
python -m unittest discover -s tests -v
```

## 13. Security and Privacy Properties

The implementation reduces the amount of data exposed to the reasoning provider:

- full raw logs are analyzed locally,
- only bounded summaries and examples become evidence,
- repository investigation returns bounded, redacted snippets,
- repository embeddings and FAISS indexes remain local,
- only the top 8 RAG chunks, capped at 30,000 characters, enter evidence,
- sensitive paths are skipped,
- prompt evidence has a hard size cap,
- repository content is never executed or modified.

With Gemini, bounded evidence is sent to a cloud provider. With Ollama, reasoning can
remain local, subject to the user's Ollama setup.

## 14. Current Limitations and Gaps

- MF4 and PCAPNG can be selected and validated, but no registered analysis tools
  process them yet.
- Tool selection is registry- and phase-based, not dynamically chosen by the LLM.
- RDF Turtle processing is heuristic and regex-based rather than a full RDF parser.
- Binary TTL analysis depends on a separately installed TShark executable.
- Gemini requires network access and a valid API key.
- Ollama requires a running local service and an installed model.
- `app/agent.py` duplicates a simple Gemini interaction and is not integrated with the
  main application architecture.
- `app/log_anaylzer.py` and `app/llm_summary.py` are currently empty placeholders;
  `log_anaylzer.py` also contains a filename spelling error.
- The embedding model must be downloaded on first use; later runs load it locally.
- Index invalidation safely rebuilds the full repository index rather than performing
  per-file vector deletion and insertion.
- There is still no calculator tool, general external API tool, LangChain workflow,
  or LangGraph workflow.

## 15. Practical Summary

The repository already provides a working first-phase analysis system: a native GUI,
validated requests, extensible local tools, bounded evidence, two reasoning providers,
cancellation, progress reporting, security controls, and focused tests. Its strongest
implemented paths are BLF analysis, TTTech/RDF TTL analysis, safe repository search,
hybrid local RAG, and evidence-grounded LLM summarization. MF4, PCAPNG, and a truly
dynamic agentic tool loop remain future work.