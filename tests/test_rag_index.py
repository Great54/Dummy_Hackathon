import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.rag.chunker import chunk_lines
from app.rag.document import RepositoryChunk
from app.rag.index import RepositoryVectorIndex
from app.rag.repository_indexer import index_repository


class FakeEmbeddings:
    model_name = "test-embeddings"

    def encode(self, texts):
        vectors = []
        for text in texts:
            lowered = text.lower()
            vectors.append(
                [
                    float(lowered.count("someip") + lowered.count("some/ip")),
                    float(lowered.count("timeout")),
                    float(lowered.count("unrelated")),
                    1.0,
                ]
            )
        return np.asarray(vectors, dtype="float32")


class RagChunkerTests(unittest.TestCase):
    def test_chunking_preserves_lines_metadata_and_overlap(self):
        chunks = list(
            chunk_lines(
                [f"line {number}\n" for number in range(1, 11)],
                "src/service.cpp",
                chunk_size_lines=4,
                overlap_lines=1,
            )
        )

        self.assertEqual(
            [(chunk.start_line, chunk.end_line) for chunk in chunks],
            [(1, 4), (4, 7), (7, 10)],
        )
        self.assertEqual(chunks[0].file_type, ".cpp")
        self.assertEqual(chunks[0].metadata["extension"], ".cpp")
        self.assertIn("line 4", chunks[0].text)
        self.assertIn("line 4", chunks[1].text)

    def test_chunks_respect_character_limit(self):
        chunks = list(
            chunk_lines(
                ["a" * 20 + "\n", "b" * 20 + "\n", "c" * 20 + "\n"],
                "config/service.txt",
                chunk_size_lines=80,
                overlap_lines=0,
                max_characters=45,
            )
        )
        self.assertTrue(all(len(chunk.text) <= 45 for chunk in chunks))
        self.assertEqual([(item.start_line, item.end_line) for item in chunks], [(1, 2), (3, 3)])

    def test_secret_values_are_redacted_before_chunking(self):
        chunk = next(chunk_lines(["service=ok API_KEY=hidden\n"], "settings.txt"))
        self.assertNotIn("hidden", chunk.text)
        self.assertIn("<redacted>", chunk.text)

    def test_chunk_round_trip_preserves_metadata(self):
        chunk = next(chunk_lines(["service_id = 0x1234\n"], "config/service.ini"))
        self.assertEqual(RepositoryChunk.from_dict(chunk.to_dict()), chunk)


class RepositoryVectorIndexTests(unittest.TestCase):
    def setUp(self):
        self.repository_temp = tempfile.TemporaryDirectory()
        self.cache_temp = tempfile.TemporaryDirectory()
        self.repository = Path(self.repository_temp.name).resolve()
        self.cache = Path(self.cache_temp.name).resolve()

    def tearDown(self):
        self.repository_temp.cleanup()
        self.cache_temp.cleanup()

    def write(self, relative_path, content, *, binary=False):
        path = self.repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def make_index(self):
        return RepositoryVectorIndex(
            cache_root=self.cache,
            embeddings=FakeEmbeddings(),
        )

    def test_index_creation_search_and_reload(self):
        self.write("src/service.cpp", "SomeIp response timeout handler\n")
        index = self.make_index()
        self.assertEqual(index.ensure(self.repository), "rebuilt")
        self.assertEqual(index.search("someip timeout", 1)[0].chunk.path, "src/service.cpp")

        reloaded = self.make_index()
        self.assertEqual(reloaded.ensure(self.repository), "cached")
        self.assertEqual(reloaded.search("someip", 1)[0].chunk.path, "src/service.cpp")

    def test_fingerprint_change_rebuilds_index(self):
        path = self.write("src/service.cpp", "old behavior\n")
        index = self.make_index()
        self.assertEqual(index.ensure(self.repository), "rebuilt")
        self.assertEqual(index.ensure(self.repository), "cached")

        path.write_text("new timeout behavior with more text\n", encoding="utf-8")
        self.assertEqual(index.ensure(self.repository), "rebuilt")

    def test_indexer_reuses_repository_file_safety_rules(self):
        self.write("src/service.cpp", "service handler\n")
        self.write(".env", "API_KEY=hidden\n")
        self.write("build/generated.cpp", "generated service\n")
        self.write("src/data.bin", b"abc\x00def", binary=True)
        large = self.repository / "src" / "large.cpp"
        with large.open("wb") as stream:
            stream.truncate(11 * 1024 * 1024)

        _, chunks, files_indexed = index_repository(self.repository)

        self.assertEqual(files_indexed, 1)
        self.assertEqual([chunk.path for chunk in chunks], ["src/service.cpp"])

    def test_corrupted_cached_index_is_rebuilt(self):
        self.write("src/service.cpp", "SomeIp response timeout handler\n")
        index = self.make_index()
        self.assertEqual(index.ensure(self.repository), "rebuilt")
        cache_directory = next(self.cache.iterdir())
        next(cache_directory.glob("index-*.faiss")).write_bytes(b"not-faiss")

        self.assertEqual(self.make_index().ensure(self.repository), "rebuilt")

    def test_empty_repository_creates_reloadable_empty_cache(self):
        index = self.make_index()
        self.assertEqual(index.ensure(self.repository), "rebuilt")
        self.assertEqual(index.search("anything", 8), [])
        self.assertEqual(self.make_index().ensure(self.repository), "cached")


if __name__ == "__main__":
    unittest.main()