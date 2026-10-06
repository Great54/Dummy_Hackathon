import unittest

from app.orchestrator.evidence import Evidence
from app.rag.document import RepositoryChunk, RetrievalResult
from app.rag.retriever import HybridRetriever, build_retrieval_query


def make_chunk(path, start, text):
    return RepositoryChunk(path, start, start + 2, text, ".cpp", f"{path}:{start}")


class FakeIndex:
    def __init__(self, chunks, vector_results):
        self.chunks = chunks
        self.vector_results = vector_results

    def search(self, query, top_k):
        return self.vector_results[:top_k]


class RagRetrieverTests(unittest.TestCase):
    def test_query_includes_log_derived_identifiers(self):
        query, terms = build_retrieval_query(
            "SOME/IP response missing",
            [Evidence("TTL Analysis", "Request observed", {"service_id": "0x1234", "method_id": "0x0002"})],
        )
        self.assertIn("0x1234", query)
        self.assertIn("0x0002", query)
        self.assertEqual(terms[:2], ["0x1234", "0x0002"])

    def test_exact_identifier_and_semantic_results_are_combined(self):
        exact = make_chunk("config/someip.json", 1, 'service_id = "0x1234"')
        semantic = make_chunk("src/response.cpp", 10, "Handle reply and availability")
        index = FakeIndex(
            [exact, semantic],
            [RetrievalResult(semantic, 0.8, "vector")],
        )
        results = HybridRetriever(index).retrieve(
            "missing response", exact_terms=["0x1234"], top_k=8
        )
        self.assertEqual({result.chunk.path for result in results}, {exact.path, semantic.path})
        self.assertIn("exact", results[0].retrieval_method)

    def test_weak_vector_noise_is_filtered_but_exact_matches_are_kept(self):
        exact = make_chunk("config/network.json", 1, '"vlanmonenable": true')
        unrelated = make_chunk("docs/unrelated.md", 1, "astronomy recipe notes")
        index = FakeIndex(
            [exact, unrelated],
            [RetrievalResult(unrelated, 0.24, "vector")],
        )

        results = HybridRetriever(index).retrieve(
            "SensorStatus unavailable", exact_terms=["vlanmonenable"]
        )

        self.assertEqual([result.chunk.path for result in results], [exact.path])
        self.assertEqual(results[0].retrieval_method, "exact")

    def test_keyword_location_boosts_matching_chunk_and_deduplicates(self):
        chunk = make_chunk("src/service.cpp", 10, "service response handler")
        index = FakeIndex([chunk], [RetrievalResult(chunk, 0.7, "vector")])
        results = HybridRetriever(index).retrieve(
            "response",
            exact_terms=["response"],
            keyword_matches=[{"file": "src/service.cpp", "line": 11}],
        )
        self.assertEqual(len(results), 1)
        self.assertIn("keyword", results[0].retrieval_method)

    def test_top_k_context_limit_and_file_diversity_are_enforced(self):
        chunks = [make_chunk("src/one.cpp", number, "timeout " * 100) for number in range(1, 10)]
        chunks += [make_chunk("src/two.cpp", 1, "timeout " * 100)]
        index = FakeIndex(chunks, [RetrievalResult(chunk, 0.9, "vector") for chunk in chunks])
        results = HybridRetriever(index).retrieve(
            "timeout", exact_terms=[], top_k=8, max_characters=3_000
        )
        self.assertLessEqual(len(results), 8)
        self.assertLessEqual(sum(len(result.chunk.text) for result in results), 3_000)
        self.assertLessEqual(sum(result.chunk.path == "src/one.cpp" for result in results), 2)


if __name__ == "__main__":
    unittest.main()