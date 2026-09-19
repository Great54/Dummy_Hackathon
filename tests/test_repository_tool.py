import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.orchestrator.evidence import AnalysisResult, Evidence
from app.orchestrator.orchestrator import AnalysisOrchestrator
from app.tools.repository_tool import (
    MAX_CONTEXT_CHARS,
    MAX_SEARCH_RESULTS,
    MAX_SEARCH_TARGETS,
    RepositoryAnalysisError,
    RepositorySecurityError,
    RepositoryTool,
    derive_search_targets,
    discover_repository_files,
    read_file,
    redact_secrets,
)
from input.models import AnalysisRequest


class StubAgent:
    def __init__(self):
        self.evidence = None

    def analyze(self, request, evidence):
        self.evidence = evidence
        return AnalysisResult("Undetermined", "Investigate", evidence)


class RepositoryToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.tool = RepositoryTool()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, content, *, binary=False):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def request(self, defect="SOME/IP response is not received"):
        return AnalysisRequest(str(self.root), defect)

    def test_repository_discovery_includes_supported_source_and_config(self):
        self.write("src/service.cpp", "void registerService() {}")
        self.write("config/service.json", '{"service_id":"0x1234"}')
        paths = {path.relative_to(self.root).as_posix() for path in discover_repository_files(self.root)}
        self.assertEqual(paths, {"config/service.json", "src/service.cpp"})

    def test_other_text_like_extension_is_discovered(self):
        self.write("config/custom.mapping", "service_id=0x1234")
        paths = {path.name for path in discover_repository_files(self.root)}
        self.assertIn("custom.mapping", paths)

    def test_search_is_case_insensitive_and_returns_line_number(self):
        self.write("src/service.cpp", "first\nRegisterSomeIpService(0x1234);\nthird\n")
        matches = self.tool.search_repository(self.root, "registersomeipservice")
        self.assertEqual(matches[0]["file"], "src/service.cpp")
        self.assertEqual(matches[0]["line"], 2)

    def test_context_read_has_line_numbers_and_bounds(self):
        self.write("src/service.cpp", "one\ntwo\nservice_id = 0x1234\nfour\nfive\n")
        result = read_file(self.root, "src/service.cpp", 1, 5)
        self.assertIn("3: service_id = 0x1234", result["content"])
        self.assertLessEqual(len(result["content"]), MAX_CONTEXT_CHARS)

    def test_read_rejects_parent_traversal(self):
        outside = self.root.parent / "outside_repo_test.txt"
        outside.write_text("secret", encoding="utf-8")
        try:
            with self.assertRaises(RepositorySecurityError):
                read_file(self.root, "../outside_repo_test.txt", 1, 1)
        finally:
            outside.unlink(missing_ok=True)

    def test_read_rejects_absolute_path(self):
        path = self.write("inside.txt", "text")
        with self.assertRaisesRegex(RepositorySecurityError, "Absolute"):
            read_file(self.root, path, 1, 1)

    def test_symlink_escape_is_not_discovered_or_read(self):
        outside_dir = tempfile.TemporaryDirectory()
        outside = Path(outside_dir.name) / "outside.txt"
        outside.write_text("service_id=0x9999", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("Creating symlinks is not permitted on this system")
            self.assertNotIn(link.resolve(), discover_repository_files(self.root))
            with self.assertRaises(RepositorySecurityError):
                read_file(self.root, "linked.txt", 1, 1)
        finally:
            outside_dir.cleanup()

    def test_binary_file_is_ignored_and_refused(self):
        self.write("src/binary.txt", b"abc\x00def", binary=True)
        self.assertEqual(discover_repository_files(self.root), [])
        with self.assertRaisesRegex(RepositoryAnalysisError, "Binary"):
            read_file(self.root, "src/binary.txt", 1, 1)

    def test_large_file_is_ignored_and_refused(self):
        path = self.root / "large.txt"
        with path.open("wb") as stream:
            stream.truncate(11 * 1024 * 1024)
        self.assertEqual(discover_repository_files(self.root), [])
        with self.assertRaisesRegex(RepositoryAnalysisError, "size limit"):
            read_file(self.root, "large.txt", 1, 1)

    def test_ignored_directories_are_not_scanned(self):
        self.write("build/generated.cpp", "service_id=0x1234")
        self.write("node_modules/package.js", "service_id=0x1234")
        self.assertEqual(discover_repository_files(self.root), [])

    def test_secret_files_are_ignored(self):
        self.write(".env", "API_KEY=do-not-expose")
        self.write("credentials.json", '{"token":"do-not-expose"}')
        self.write("private.pem", "private")
        self.assertEqual(discover_repository_files(self.root), [])

    def test_secret_values_are_redacted_in_matches_and_context(self):
        self.write(
            "config/settings.txt",
            'service_id=0x1234 API_KEY=abc123 "token": "xyz789"',
        )
        matches = self.tool.search_repository(self.root, "service_id")
        rendered = matches[0]["match"] + read_file(
            self.root, "config/settings.txt", 1, 1
        )["content"]
        self.assertNotIn("abc123", rendered)
        self.assertNotIn("xyz789", rendered)
        self.assertIn("<redacted>", rendered)

    def test_result_count_is_bounded(self):
        self.write("src/many.cpp", "\n".join("timeout handling" for _ in range(100)))
        matches = self.tool.search_repository(self.root, "timeout", max_results=1000)
        self.assertEqual(len(matches), MAX_SEARCH_RESULTS)

    def test_search_targets_are_bounded_and_prioritize_evidence_ids(self):
        evidence = [
            Evidence(
                "TTL",
                "Observed SOME/IP",
                {
                    "service_id": "0x1234",
                    "instance_id": "0x0001",
                    "method_id": "0x0002",
                    "many": [f"term{index}" for index in range(100)],
                },
            )
        ]
        targets = derive_search_targets(
            "SOME/IP response timeout communication service method event payload",
            evidence,
        )
        self.assertLessEqual(len(targets), MAX_SEARCH_TARGETS)
        self.assertEqual(targets[:3], ["0x1234", "0x0001", "0x0002"])

    def test_metric_counts_are_not_used_as_search_targets(self):
        evidence = [
            Evidence(
                "TTL",
                "Observed SOME/IP traffic",
                {
                    "error_record_count": 8487,
                    "someip_message_count": 6102,
                    "someip.serviceid": "0x1234",
                },
            )
        ]
        targets = derive_search_targets("SOME/IP response missing", evidence)
        self.assertIn("0x1234", targets)
        self.assertNotIn("8487", targets)
        self.assertNotIn("6102", targets)

    def test_read_rejects_excessive_line_range(self):
        self.write("src/service.cpp", "line\n" * 20)
        with self.assertRaisesRegex(RepositoryAnalysisError, "context limit"):
            read_file(self.root, "src/service.cpp", 1, 20)

    def test_empty_repository_returns_bounded_no_match_evidence(self):
        evidence = self.tool.run(self.request())
        self.assertFalse(evidence.details["evidence_found"])
        self.assertEqual(evidence.details["matches"], [])
        self.assertEqual(evidence.details["files_scanned"], 0)

    def test_missing_repository_is_not_applicable_and_run_is_controlled(self):
        missing = self.root / "missing"
        request = AnalysisRequest(str(missing), "SOME/IP failure")
        self.assertFalse(self.tool.is_applicable(request))
        with self.assertRaisesRegex(RepositoryAnalysisError, "does not exist"):
            self.tool.run(request)

    def test_repository_tool_is_applicable_without_logs(self):
        self.assertTrue(self.tool.is_applicable(self.request()))

    def test_selected_log_file_inside_repository_is_excluded(self):
        ttl = self.write("capture.ttl", "SOME/IP service 0x1234")
        request = AnalysisRequest(str(self.root), "SOME/IP", ttl_path=str(ttl))
        evidence = self.tool.run(request)
        self.assertEqual(evidence.details["files_discovered"], 0)

    def test_prior_evidence_guides_repository_search(self):
        self.write("config/someip.json", '{"service_id":"0x1234","timeout":500}')
        prior = [Evidence("TTL", "request observed", {"service_id": "0x1234"})]
        evidence = self.tool.run(self.request(), prior_evidence=prior)
        self.assertTrue(evidence.details["evidence_found"])
        self.assertIn("0x1234", evidence.details["search_targets"])
        self.assertEqual(evidence.details["matches"][0]["file"], "config/someip.json")

    def test_orchestrator_runs_log_phase_before_repository_phase(self):
        self.write("src/service.cpp", "service_id = 0x1234")

        class FakeLogTool:
            name = "Fake Log Analysis"
            phase = 0

            def is_applicable(self, request):
                return True

            def run(self, request, on_progress=None, prior_evidence=None):
                return Evidence("Fake Log", "Observed request", {"service_id": "0x1234"})

        agent = StubAgent()
        with patch(
            "app.orchestrator.orchestrator.get_applicable_tools",
            return_value=[RepositoryTool(), FakeLogTool()],
        ):
            result = AnalysisOrchestrator(agent).run(self.request())

        self.assertEqual([item.source for item in result.evidence], ["Fake Log", "Repository Analysis"])
        repository = result.evidence[1]
        self.assertTrue(repository.details["evidence_found"])
        self.assertIn("0x1234", repository.details["search_targets"])

    def test_no_log_orchestrator_path_produces_repository_evidence(self):
        self.write("src/service.cpp", "void handleSomeIpResponse();")
        result = AnalysisOrchestrator(StubAgent()).run(self.request())
        sources = [item.source for item in result.evidence]
        self.assertEqual(sources, ["Repository Analysis"])
        self.assertTrue(result.evidence[0].details["evidence_found"])


if __name__ == "__main__":
    unittest.main()
