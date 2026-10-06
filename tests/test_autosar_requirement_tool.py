import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch

from app.agent.reasoning_agent import ReasoningAgent
from app.orchestrator.evidence import AnalysisResult, Evidence
from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.tools.autosar_requirement_tool import (
    AUTOSAR_BASE_URL,
    AUTOSARRequirementTool,
    AutosarMetadataCache,
    MAX_REQUIREMENT_EXCERPT_CHARACTERS,
    _explicit_behavior_match,
    _document_score,
    extract_requirement_candidates,
    extract_requirement_ids,
    generate_targeted_queries,
    is_official_document_url,
    is_official_autosar_url,
    rank_requirement_candidates,
    select_autosar_release,
    select_autosar_platform,
)
from input.models import AnalysisRequest


OFFICIAL_E2E_URL = (
    "https://www.autosar.org/fileadmin/standards/R25-11/FO/"
    "AUTOSAR_FO_RS_E2E.pdf"
)
OFFICIAL_E2E_DOCUMENT = {
    "release": "R25-11",
    "platform": "Foundation",
    "document": "Requirements on E2E",
    "document_id": "AUTOSAR_FO_RS_E2E",
    "source_url": OFFICIAL_E2E_URL,
}
REAL_OFFICIAL_REQUIREMENT_ID = "RS_E2E_08544"
REAL_COM_REQUIREMENT_ID = "SRS_Com_02089"


class CapturingAgent:
    def __init__(self):
        self.evidence = None

    def analyze(self, request, evidence):
        self.evidence = evidence
        return AnalysisResult(
            root_cause="Assessment is limited to the supplied evidence.",
            recommendation="Collect additional runtime evidence.",
            evidence=evidence,
            confidence="low",
        )


class FakeClient:
    def __init__(self):
        self.prompt = ""

    def generate_json(self, prompt):
        self.prompt = prompt
        return json.dumps(
            {
                "root_cause": "Insufficient evidence to determine the root cause.",
                "recommendation": "Collect additional runtime evidence.",
                "confidence": "low",
                "hypotheses": [],
                "next_investigation_steps": ["Capture the relevant communication signals."],
            }
        )


class AutosarRequirementToolTests(unittest.TestCase):
    def make_tool(self, directory):
        return AUTOSARRequirementTool(
            cache=AutosarMetadataCache(Path(directory) / "cache")
        )

    def test_queries_are_targeted_and_derived_from_defect_and_evidence(self):
        request = AnalysisRequest(
            ".",
            "SensorStatus becomes UNAVAILABLE during SOME/IP service discovery.",
        )
        evidence = [
            Evidence("TTL Analysis", "SOME/IP-SD subscription timed out", {"protocol": "SOME/IP-SD"}),
            Evidence(
                "Repository RAG",
                "FunctionStatus is mapped by the communication manager",
                {"chunks": [{"path": "src/network.c", "text": "SensorStatus"}]},
            ),
        ]

        queries = generate_targeted_queries(request, evidence)

        self.assertLessEqual(len(queries), 3)
        self.assertTrue(any("service discovery" in query.casefold() for query in queries))
        self.assertTrue(any("signal" in query.casefold() for query in queries))
        self.assertTrue(all(request.defect_description not in query for query in queries))

    def test_unrelated_timeout_does_not_force_an_e2e_query(self):
        request = AnalysisRequest(".", "COM signal timeout causes unavailable data")
        queries = generate_targeted_queries(request, [])
        self.assertFalse(any("E2E" in query for query in queries))

    def test_scanned_tool_summary_does_not_trigger_can_query(self):
        request = AnalysisRequest(".", "SensorStatus becomes unavailable intermittently")
        evidence = [Evidence("Repository Analysis", "Scanned 100 source files", {})]

        queries = generate_targeted_queries(request, evidence)

        self.assertFalse(any("CAN CAN-FD" in query for query in queries))

    def test_official_domain_and_document_url_validation(self):
        self.assertTrue(is_official_autosar_url("https://www.autosar.org/standards"))
        self.assertTrue(is_official_autosar_url("https://autosar.org/standards"))
        self.assertFalse(is_official_autosar_url("http://www.autosar.org/"))
        self.assertFalse(is_official_autosar_url("https://autosar.org.attacker.test/"))
        self.assertFalse(is_official_autosar_url("https://user@www.autosar.org/"))
        self.assertTrue(is_official_document_url(OFFICIAL_E2E_URL, "R25-11"))
        self.assertFalse(is_official_document_url(OFFICIAL_E2E_URL, "R24-11"))
        self.assertFalse(
            is_official_document_url(
                "https://www.autosar.org/fileadmin/standards/R25-11/CP/../../evil.pdf",
                "R25-11",
            )
        )
        self.assertFalse(
            is_official_document_url(
                "https://www.autosar.org/fileadmin/standards/R25-11/CP/%2e%2e/evil.pdf",
                "R25-11",
            )
        )

    def test_requirement_id_extraction_uses_only_ids_present_in_text(self):
        identifiers = extract_requirement_ids(
            f"A source reference {REAL_OFFICIAL_REQUIREMENT_ID!r} is not bracketed; "
            f"the official notation is [{REAL_OFFICIAL_REQUIREMENT_ID}]."
        )
        self.assertEqual(identifiers, [REAL_OFFICIAL_REQUIREMENT_ID])
        self.assertEqual(extract_requirement_ids("no official requirement identifier"), [])

    def test_official_search_metadata_parsing_filters_domains_and_releases(self):
        html = f"""
        <h1>AUTOSAR Documents</h1>
        <p>39 Documents found</p>
        <a href="{OFFICIAL_E2E_URL}">Requirements on E2E</a>
        <a href="https://example.test/AUTOSAR_FO_RS_E2E.pdf">Third party</a>
        <a href="https://www.autosar.org/fileadmin/standards/R24-11/FO/old.pdf">Old release</a>
        """
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.object(tool, "_fetch", return_value=html.encode("utf-8")) as fetch:
                documents = tool._search_official("E2E timeout requirements", "R25-11")

        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0]["document_id"], "AUTOSAR_FO_RS_E2E")
        self.assertEqual(documents[0]["platform"], "Foundation")
        self.assertIn("R25-11", fetch.call_args.args[0])

    def test_candidate_document_ranking_prefers_matching_requirement_spec(self):
        diagnostics = {
            "document": "Requirements on Diagnostics",
            "document_id": "AUTOSAR_FO_RS_Diagnostics",
        }
        e2e = {
            "document": "Requirements on E2E",
            "document_id": "AUTOSAR_FO_RS_E2E",
        }

        self.assertGreater(
            _document_score(e2e, "E2E protection counter timeout"),
            _document_score(diagnostics, "E2E protection counter timeout"),
        )

    def test_cp_module_and_platform_preference_rank_cp_com_over_ap_neighbors(self):
        request = AnalysisRequest(".", "SensorStatus becomes unavailable")
        evidence = [
            Evidence("Repository RAG", "COM_RX_TIMEOUT updates SensorStatus", {})
        ]
        preference = select_autosar_platform(request, evidence)
        cp_document = {
            "document": "Requirements on Communication",
            "document_id": "AUTOSAR_CP_RS_COM",
            "platform": "CP",
        }
        ap_document = {
            "document": "Specification of Raw Data Stream",
            "document_id": "AUTOSAR_AP_SWS_RawDataStream",
            "platform": "AP",
        }

        self.assertEqual(preference, "CP")
        self.assertGreater(
            _document_score(cp_document, "AUTOSAR COM communication signal invalidation", preference),
            _document_score(ap_document, "AUTOSAR COM communication signal invalidation", preference),
        )

    def test_shared_document_keeps_its_strongest_targeted_query(self):
        document = {
            "document": "Requirements on Communication",
            "document_id": "AUTOSAR_CP_RS_COM",
            "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf",
            "platform": "CP",
        }
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch.object(
                    tool,
                    "_search_official",
                    side_effect=[[dict(document)], [dict(document)]],
                ), patch.object(tool, "_fetch_pdf", return_value=b"%PDF"), patch(
                    "app.tools.autosar_requirement_tool._extract_pdf_pages",
                    return_value=[],
                ), patch.object(tool.cache, "put") as cache_put:
                    tool.run(
                        AnalysisRequest(
                            directory,
                            "SensorStatus becomes UNAVAILABLE during COM signal timeout",
                        ),
                        prior_evidence=[
                            Evidence(
                                "Repository RAG",
                                "COM_RX_TIMEOUT updates SensorStatus",
                                {"chunks": [{"path": "src/communication.c", "text": "COM_RX_TIMEOUT"}]},
                            )
                        ],
                    )

        selected_query = cache_put.call_args.args[0]
        self.assertIn("AUTOSAR COM communication signal", selected_query)

    def test_platform_preference_remains_unknown_without_explicit_markers(self):
        request = AnalysisRequest(".", "Communication-related data is unavailable")
        self.assertIsNone(select_autosar_platform(request, []))

    def test_release_selection_prefers_repository_then_configuration_then_current(self):
        request = AnalysisRequest(".", "Intermittent communication")
        repository_evidence = [
            Evidence("Repository Analysis", "Project is configured for AUTOSAR R23-11", {})
        ]
        with patch.dict(os.environ, {"AUTOSAR_RELEASE": "R24-11"}):
            self.assertEqual(
                select_autosar_release(request, repository_evidence),
                ("R23-11", "repository evidence"),
            )
            self.assertEqual(
                select_autosar_release(request, []),
                ("R24-11", "AUTOSAR_RELEASE configuration"),
            )
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(select_autosar_release(request, []), ("R25-11", "current official release"))

    def test_candidate_metadata_and_applicability_come_from_document_context(self):
        source_context = f"[{REAL_OFFICIAL_REQUIREMENT_ID}]"
        candidates = extract_requirement_candidates(
            [source_context],
            OFFICIAL_E2E_DOCUMENT,
            "E2E protection timeout",
            [],
        )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["requirement_id"], REAL_OFFICIAL_REQUIREMENT_ID)
        self.assertEqual(candidate["document_id"], "AUTOSAR_FO_RS_E2E")
        self.assertEqual(candidate["release"], "R25-11")
        self.assertEqual(candidate["source_url"], OFFICIAL_E2E_URL)
        self.assertLessEqual(len(candidate["requirement_summary"]), MAX_REQUIREMENT_EXCERPT_CHARACTERS)
        self.assertIsNone(candidate["requirement_title"])

    def test_actual_normative_excerpt_is_bounded_and_ranked_above_a_reference(self):
        reference = f"Table references the feature [{REAL_OFFICIAL_REQUIREMENT_ID}]"
        normative = (
            f"[{REAL_OFFICIAL_REQUIREMENT_ID}] E2E protocol shall provide a timeout "
            "detection mechanism"
        )
        candidates = extract_requirement_candidates(
            [reference, normative],
            OFFICIAL_E2E_DOCUMENT,
            "E2E protection timeout communication",
            [Evidence("TTL Analysis", "E2E timeout observed", {"protocol": "E2E"})],
        )

        self.assertEqual(len(candidates), 1)
        self.assertIn("shall provide", candidates[0]["requirement_summary"])
        self.assertLessEqual(
            len(candidates[0]["requirement_summary"]),
            MAX_REQUIREMENT_EXCERPT_CHARACTERS,
        )
        self.assertGreater(candidates[0]["confidence"], 0.25)

    def test_official_com_signal_timeout_requirement_matches_supplied_behavior(self):
        document = {
            "release": "R25-11",
            "platform": "CP",
            "document": "Requirements on Communication",
            "document_id": "AUTOSAR_CP_RS_COM",
            "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf",
        }
        evidence = [
            Evidence(
                "TTL Analysis",
                "COM_RX_TIMEOUT 550 ms: received signal becomes invalid and SensorStatus is UNAVAILABLE",
                {"signal": "SensorStatus", "timeout_ms": 550},
            ),
            Evidence(
                "Repository RAG",
                "COM_RX_TIMEOUT drives FunctionStatus SensorStatus to UNAVAILABLE",
                {"chunks": [{"path": "src/communication.c", "text": "COM_RX_TIMEOUT; SensorStatus = UNAVAILABLE;"}]},
            ),
        ]
        source_text = (
            f"[{REAL_COM_REQUIREMENT_ID}] The AUTOSAR COM module shall provide "
            "two configurable options to handle signal timeouts. Receiver-side "
            "the AUTOSAR COM module shall provide options if a signal timeout occurs."
        )

        candidates = extract_requirement_candidates(
            [source_text],
            document,
            "AUTOSAR COM communication signal invalidation reception timeout requirements",
            evidence,
        )

        self.assertEqual(candidates[0]["requirement_id"], REAL_COM_REQUIREMENT_ID)
        self.assertEqual(candidates[0]["applicability"], "DIRECTLY APPLICABLE")
        self.assertIn("signal timeouts", candidates[0]["requirement_summary"])

    def test_requirement_candidates_are_ranked_by_source_context_confidence(self):
        low = {
            "requirement_id": "RS_E2E_08545",
            "confidence": 0.31,
            "requirement_summary": "short excerpt",
        }
        high = {
            "requirement_id": REAL_OFFICIAL_REQUIREMENT_ID,
            "confidence": 0.81,
            "requirement_summary": "short excerpt",
        }
        ranked = rank_requirement_candidates([low, high])
        self.assertEqual(ranked[0]["requirement_id"], REAL_OFFICIAL_REQUIREMENT_ID)

    def test_direct_applicability_requires_specific_normative_behavior(self):
        query = {"e2e", "timeout"}
        evidence = {"e2e", "timeout"}
        self.assertTrue(
            _explicit_behavior_match(
                query,
                evidence,
                "E2E protocol shall provide a timeout detection mechanism",
            )
        )
        self.assertFalse(
            _explicit_behavior_match(
                query,
                evidence,
                "Each E2E profile shall use an appropriate subset of sequence counter and timeout mechanisms",
            )
        )

    def test_no_match_is_explicit_and_does_not_claim_a_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch.object(tool, "_search_official", return_value=[]):
                    evidence = tool.run(
                        AnalysisRequest(directory, "A fictional proprietary sensor state flips")
                    )

        self.assertEqual(evidence.details["status"], "no_match")
        self.assertEqual(evidence.summary, "No matching AUTOSAR requirement identified")
        self.assertEqual(evidence.details["requirements"], [])
        self.assertTrue(evidence.details["lookup_complete"])

    def test_document_scan_cap_is_unavailable_not_no_match(self):
        first = {
            "document": "Requirements on E2E",
            "document_id": "AUTOSAR_FO_RS_E2E",
            "source_url": OFFICIAL_E2E_URL,
            "platform": "Foundation",
        }
        second = {
            "document": "Requirements on Diagnostics",
            "document_id": "AUTOSAR_FO_RS_Diagnostics",
            "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/FO/AUTOSAR_FO_RS_Diagnostics.pdf",
            "platform": "Foundation",
        }
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch("app.tools.autosar_requirement_tool.MAX_DOCUMENTS_TO_READ", 1):
                    with patch.object(tool, "_search_official", side_effect=[[first], [second]]):
                        with patch.object(tool, "_fetch_pdf", return_value=b"%PDF"):
                            with patch(
                                "app.tools.autosar_requirement_tool._extract_pdf_pages",
                                return_value=[],
                            ):
                                evidence = tool.run(
                                    AnalysisRequest(directory, "SOME/IP service discovery behavior")
                                )

        self.assertEqual(evidence.details["status"], "unavailable")
        self.assertFalse(evidence.details["lookup_complete"])
        self.assertIn("document_scan_limit_reached", evidence.details["failure_categories"])

    def test_network_failure_and_timeout_return_unavailable_evidence(self):
        for error, category in ((URLError("offline"), "network_error"), (TimeoutError(), "timeout")):
            with self.subTest(category=category), tempfile.TemporaryDirectory() as directory:
                tool = self.make_tool(directory)
                with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                    with patch.object(tool, "_search_official", side_effect=error):
                        evidence = tool.run(
                            AnalysisRequest(directory, "COM signal reception timeout")
                        )
                self.assertEqual(evidence.details["status"], "unavailable")
                self.assertEqual(evidence.summary, "Official AUTOSAR lookup could not be completed.")
                self.assertIn(category, evidence.details["failure_categories"])

    def test_malformed_search_result_is_unavailable_not_a_false_no_match(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch.object(tool, "_fetch", return_value=b"<html>proxy error</html>"):
                    evidence = tool.run(
                        AnalysisRequest(directory, "COM signal invalidation timeout")
                    )
        self.assertEqual(evidence.details["status"], "unavailable")

    def test_cache_key_includes_query_release_document_and_source_url(self):
        base = AutosarMetadataCache.key(
            "E2E timeout", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL
        )
        self.assertNotEqual(base, AutosarMetadataCache.key("E2E counter", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL))
        self.assertNotEqual(base, AutosarMetadataCache.key("E2E timeout", "R24-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL))
        self.assertNotEqual(base, AutosarMetadataCache.key("E2E timeout", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL + "?x=1"))

    def test_cache_reuses_bounded_official_metadata_only(self):
        query = "E2E timeout"
        requirement = {
            "release": "R25-11",
            "platform": "Foundation",
            "document": "Requirements on E2E",
            "document_id": "AUTOSAR_FO_RS_E2E",
            "requirement_id": REAL_OFFICIAL_REQUIREMENT_ID,
            "requirement_summary": "Short source excerpt",
            "source_url": OFFICIAL_E2E_URL,
            "confidence": 0.7,
            "applicability": "RELATED",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = AutosarMetadataCache(Path(directory))
            cache.put(query, "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL, [requirement])
            result = cache.get(query, "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL)
            cache_path = Path(directory) / "requirements.json"
            cached_text = cache_path.read_text(encoding="utf-8")

        self.assertEqual(result[0]["requirement_id"], REAL_OFFICIAL_REQUIREMENT_ID)
        self.assertNotIn("%PDF", cached_text)
        self.assertLess(len(cached_text), 10_000)
        self.assertIsNone(cache.get("different query", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL))

    def test_cached_requirement_is_rescored_for_current_evidence(self):
        document = {
            "release": "R25-11",
            "platform": "CP",
            "document": "Requirements on Communication",
            "document_id": "AUTOSAR_CP_RS_COM",
            "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf",
        }
        request = AnalysisRequest(".", "COM signal timeout is reported")
        prior = [
            Evidence(
                "Repository RAG",
                "COM module is present in the implementation",
                {"chunks": [{"path": "src/com.c", "text": "COM signal path forwards data"}]},
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            cache = AutosarMetadataCache(Path(directory))
            queries = generate_targeted_queries(request, prior)
            cached_requirement = {
                "release": "R25-11",
                "platform": "CP",
                "document": document["document"],
                "document_id": document["document_id"],
                "requirement_id": REAL_COM_REQUIREMENT_ID,
                "requirement_summary": (
                    f"[{REAL_COM_REQUIREMENT_ID}] The AUTOSAR COM module shall provide "
                    "configurable options to handle signal timeouts."
                ),
                "source_url": document["source_url"],
                "source_page": 18,
                "confidence": 0.99,
                "applicability": "DIRECTLY APPLICABLE",
            }
            cache.put(queries[0], "R25-11", document["document_id"], document["source_url"], [cached_requirement])
            tool = AUTOSARRequirementTool(cache=cache)
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch.object(tool, "_search_official", return_value=[document]):
                    evidence = tool.run(request, prior_evidence=prior)

        candidate = next(
            item for item in evidence.details["requirements"]
            if item["requirement_id"] == REAL_COM_REQUIREMENT_ID
        )
        self.assertNotEqual(candidate["applicability"], "DIRECTLY APPLICABLE")

    def test_cache_honors_environment_configured_after_tool_construction(self):
        with tempfile.TemporaryDirectory() as directory:
            original_root = Path(directory) / "original"
            configured_root = Path(directory) / "configured"
            cache = AutosarMetadataCache(original_root)
            with patch.dict(os.environ, {"AUTOSAR_CACHE_DIR": str(configured_root)}):
                cache.put(
                    "query", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL, []
                )
                self.assertTrue((configured_root / "requirements.json").is_file())
                self.assertFalse((original_root / "requirements.json").exists())

    def test_cache_refuses_non_official_source_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = AutosarMetadataCache(Path(directory))
            cache.put("query", "R25-11", "doc", "https://example.test/doc.pdf", [])
            self.assertFalse((Path(directory) / "requirements.json").exists())

    def test_cache_recovers_from_malformed_local_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = AutosarMetadataCache(Path(directory))
            cache.path.write_text('{"bad-entry":"not-an-object"}', encoding="utf-8")
            cache.put("query", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL, [])
            result = cache.get("query", "R25-11", "AUTOSAR_FO_RS_E2E", OFFICIAL_E2E_URL)

        self.assertEqual(result, [])

    def test_document_fetch_rejects_traversal_before_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = self.make_tool(directory)
            with patch.object(tool, "_fetch") as fetch:
                with self.assertRaises(ValueError):
                    tool._fetch_pdf(
                        "https://www.autosar.org/fileadmin/standards/R25-11/CP/%2e%2e/outside.pdf",
                        "R25-11",
                    )
        fetch.assert_not_called()

    def test_autosar_evidence_flows_after_repository_and_before_reasoning(self):
        with tempfile.TemporaryDirectory() as repository:
            Path(repository, "src").mkdir()
            Path(repository, "src", "comm.c").write_text(
                "COM signal timeout makes SensorStatus unavailable\n", encoding="utf-8"
            )
            autosar_tool = next(
                tool for tool in __import__("app.tools.registry", fromlist=["get_registered_tools"]).get_registered_tools()
                if isinstance(tool, AUTOSARRequirementTool)
            )
            observed_prior_sources = []
            original_run = autosar_tool.run

            def capture_prior(request, on_progress=None, prior_evidence=None):
                observed_prior_sources.extend(item.source for item in prior_evidence or [])
                return original_run(request, on_progress, prior_evidence)

            agent = CapturingAgent()
            with patch.dict(os.environ, {"RAG_ENABLED": "false"}):
                with patch.object(autosar_tool, "_search_official", return_value=[]):
                    with patch.object(autosar_tool, "run", side_effect=capture_prior):
                        result = AnalysisOrchestrator(agent).run(
                            AnalysisRequest(repository, "COM signal timeout makes data unavailable")
                        )

        sources = [item.source for item in result.evidence]
        self.assertIn("Repository Analysis", observed_prior_sources)
        self.assertIn("Repository Analysis", sources)
        self.assertIn("AUTOSAR Official Specification", sources)
        self.assertLess(sources.index("Repository Analysis"), sources.index("AUTOSAR Official Specification"))
        self.assertEqual(agent.evidence, result.evidence)

    def test_end_to_end_communication_defect_uses_log_repository_rag_then_autosar(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            capture = repository / "communication.ttl"
            capture.write_text("# synthetic test capture\n", encoding="utf-8")
            prior_seen = {}

            class StageTool:
                def __init__(self, name, phase, evidence):
                    self.name = name
                    self.phase = phase
                    self.evidence = evidence

                def is_applicable(self, request):
                    return True

                def run(self, request, on_progress=None, prior_evidence=None):
                    prior_seen[self.name] = [item.source for item in prior_evidence or []]
                    return self.evidence

            log_tool = StageTool(
                "TTL Analysis",
                20,
                Evidence(
                    "TTL Analysis",
                    "COM reception timeout observed while SensorStatus is UNAVAILABLE.",
                    {"status": "UNAVAILABLE", "timeout_ms": 550},
                ),
            )
            repository_tool = StageTool(
                "Repository Analysis",
                100,
                Evidence(
                    "Repository Analysis",
                    "Found FunctionStatus and SensorStatus implementation references.",
                    {"matches": [{"file": "src/diagnostic.c", "line": 18}]},
                ),
            )
            rag_tool = StageTool(
                "Repository RAG",
                110,
                Evidence(
                    "Repository RAG",
                    "Retrieved a bounded diagnostic source chunk.",
                    {
                        "chunks": [
                            {
                                "path": "src/diagnostic.c",
                                "start_line": 16,
                                "end_line": 20,
                                "text": "FunctionStatus SensorStatus = UNAVAILABLE;",
                            }
                        ]
                    },
                ),
            )
            autosar_tool = self.make_tool(repository / "cache")
            original_autosar_run = autosar_tool.run

            def capture_autosar_prior(request, on_progress=None, prior_evidence=None):
                prior_seen["AUTOSAR Requirement Analysis"] = [
                    item.source for item in prior_evidence or []
                ]
                return original_autosar_run(request, on_progress, prior_evidence)

            tools = [log_tool, repository_tool, rag_tool, autosar_tool]
            client = FakeClient()
            request = AnalysisRequest(
                str(repository),
                "Communication-related data becomes unavailable intermittently. Analyze the log and implementation, then assess AUTOSAR applicability.",
                ttl_path=str(capture),
            )
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                with patch(
                    "app.orchestrator.orchestrator.get_applicable_tools",
                    return_value=tools,
                ), patch.object(autosar_tool, "_search_official", return_value=[]):
                    with patch.object(
                        autosar_tool, "run", side_effect=capture_autosar_prior
                    ):
                        result = AnalysisOrchestrator(ReasoningAgent(client)).run(request)

        self.assertIn("TTL Analysis", prior_seen["Repository Analysis"] + prior_seen["Repository RAG"])
        self.assertIn("Repository Analysis", prior_seen["Repository RAG"])
        self.assertIn("TTL Analysis", prior_seen["AUTOSAR Requirement Analysis"])
        self.assertIn("Repository RAG", prior_seen["AUTOSAR Requirement Analysis"])
        self.assertIn("AUTOSAR Official Specification", [item.source for item in result.evidence])
        self.assertIn(
            "No matching AUTOSAR requirement was identified from the searched official AUTOSAR sources.",
            result.correlation,
        )
        self.assertIn('"status":"no_match"', client.prompt)

    def test_gemini_prompt_contains_bounded_official_requirement_fields(self):
        client = FakeClient()
        evidence = Evidence(
            "AUTOSAR Official Specification",
            "Retrieved an official AUTOSAR requirement.",
            {
                "status": "matched",
                "release": "R25-11",
                "platform": "Foundation",
                "requirements": [
                    {
                        "requirement_id": REAL_OFFICIAL_REQUIREMENT_ID,
                        "document": "Requirements on E2E",
                        "release": "R25-11",
                        "platform": "Foundation",
                        "requirement_summary": "Short source-grounded excerpt",
                        "applicability": "RELATED",
                        "source_url": OFFICIAL_E2E_URL,
                        "relevance_reason": "E2E timeout concept",
                        "confidence": 0.7,
                    }
                ],
            },
        )
        ReasoningAgent(client).analyze(
            AnalysisRequest(".", "E2E timeout"), [evidence]
        )
        self.assertIn("AUTOSAR REQUIREMENT EVIDENCE", client.prompt)
        self.assertIn(REAL_OFFICIAL_REQUIREMENT_ID, client.prompt)
        self.assertIn(OFFICIAL_E2E_URL, client.prompt)
        self.assertIn("Never infer or invent an AUTOSAR requirement ID", client.prompt)

    def test_no_match_instruction_is_in_reasoning_prompt(self):
        client = FakeClient()
        evidence = Evidence(
            "AUTOSAR Official Specification",
            "No matching AUTOSAR requirement identified",
            {"status": "no_match", "release": "R25-11", "requirements": []},
            severity="warning",
        )
        result = ReasoningAgent(client).analyze(
            AnalysisRequest(".", "proprietary sensor state"), [evidence]
        )
        self.assertIn(
            "No matching AUTOSAR requirement was identified from the searched official AUTOSAR sources.",
            client.prompt,
        )
        self.assertIn(
            "No matching AUTOSAR requirement was identified from the searched official AUTOSAR sources.",
            result.correlation,
        )

    def test_incomplete_lookup_scope_is_visible_in_correlation_and_prompt(self):
        client = FakeClient()
        evidence = Evidence(
            "AUTOSAR Official Specification",
            "Retrieved an official AUTOSAR requirement candidate; additional documents were not inspected.",
            {
                "status": "matched",
                "release": "R25-11",
                "lookup_complete": False,
                "failure_categories": ["document_scan_limit_reached"],
                "requirements": [
                    {
                        "requirement_id": REAL_COM_REQUIREMENT_ID,
                        "document": "Requirements on Communication",
                        "document_id": "AUTOSAR_CP_RS_COM",
                        "release": "R25-11",
                        "platform": "CP",
                        "applicability": "RELATED",
                        "requirement_summary": "Short official excerpt.",
                        "source_url": "https://www.autosar.org/fileadmin/standards/R25-11/CP/AUTOSAR_CP_RS_COM.pdf",
                        "confidence": 0.7,
                    }
                ],
            },
        )
        result = ReasoningAgent(client).analyze(
            AnalysisRequest(".", "COM signal timeout"), [evidence]
        )

        self.assertIn("Search was bounded", result.correlation)
        self.assertIn('"lookup_complete":false', client.prompt)

    def test_model_cannot_introduce_an_unretrieved_autosar_id(self):
        client = FakeClient()
        response = {
            "root_cause": f"AUTOSAR requirement [{REAL_OFFICIAL_REQUIREMENT_ID}] applies.",
            "recommendation": "Review the source.",
            "correlation": f"The result cites [{REAL_OFFICIAL_REQUIREMENT_ID}].",
            "confidence": "low",
            "hypotheses": [],
            "next_investigation_steps": [],
        }
        client.generate_json = lambda prompt: json.dumps(response)
        evidence = Evidence(
            "AUTOSAR Official Specification",
            "Official requirement evidence.",
            {
                "status": "matched",
                "requirements": [
                    {
                        "requirement_id": "RS_E2E_08545",
                        "release": "R25-11",
                        "source_url": OFFICIAL_E2E_URL,
                    }
                ],
                "evidence_found": True,
            },
        )

        result = ReasoningAgent(client).analyze(
            AnalysisRequest(".", "E2E timeout"), [evidence]
        )

        self.assertNotIn(REAL_OFFICIAL_REQUIREMENT_ID, result.root_cause)
        self.assertIn("unverified AUTOSAR reference omitted", result.root_cause)
        self.assertNotIn(REAL_OFFICIAL_REQUIREMENT_ID, result.raw_ai_response)


@unittest.skipUnless(
    os.getenv("RUN_AUTOSAR_LIVE_TEST") == "1",
    "Set RUN_AUTOSAR_LIVE_TEST=1 to query official autosar.org",
)
class AutosarLiveIntegrationTests(unittest.TestCase):
    def test_live_official_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = AUTOSARRequirementTool(
                cache=AutosarMetadataCache(Path(directory) / "cache")
            )
            with patch.dict(os.environ, {"AUTOSAR_OFFLINE": ""}):
                evidence = tool.run(
                    AnalysisRequest(
                        directory,
                        "E2E communication timeout and invalid data counter",
                    )
                )
        self.assertIn(evidence.details["status"], {"matched", "no_match", "unavailable"})
        if evidence.details["status"] == "matched":
            self.assertTrue(evidence.details["requirements"])
            for item in evidence.details["requirements"]:
                self.assertTrue(is_official_document_url(item["source_url"], item["release"]))


if __name__ == "__main__":
    unittest.main()