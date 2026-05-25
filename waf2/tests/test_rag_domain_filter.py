"""Tests for RAG domain filtering (RQ4 three-configuration support)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from waf2.rag.schema import KnowledgeEntry


# ---------- KnowledgeEntry domain ----------


def test_entry_default_domain():
    e = KnowledgeEntry(text="test payload", category="sql_injection")
    assert e.metadata.get("domain") == "generic"


def test_entry_explicit_domain():
    e = KnowledgeEntry(
        text="test payload",
        category="prompt_injection",
        metadata={"domain": "mcp"},
    )
    assert e.metadata["domain"] == "mcp"


def test_entry_domain_in_to_dict():
    e = KnowledgeEntry(text="test", category="xss", metadata={"domain": "mcp"})
    d = e.to_dict()
    assert d["metadata"]["domain"] == "mcp"


# ---------- Processor domains ----------


def test_payloads_processor_domain():
    from waf2.rag.scripts.processors import PayloadsAllTheThingsProcessor
    assert PayloadsAllTheThingsProcessor.domain == "generic"


def test_owasp_processor_domain():
    from waf2.rag.scripts.processors import OwaspCrsProcessor
    assert OwaspCrsProcessor.domain == "generic"


def test_prompt_injection_processor_domain():
    from waf2.rag.scripts.processors import PromptInjectionProcessor
    assert PromptInjectionProcessor.domain == "mcp"


def test_benign_processor_domain():
    from waf2.rag.scripts.processors import BenignHardNegativeProcessor
    assert BenignHardNegativeProcessor.domain == "mcp"


# ---------- KnowledgeBase domain_filter ----------


def test_query_passes_domain_filter():
    """Verify domain_filter is passed to ChromaDB where clause."""
    mock_collection = MagicMock()
    mock_collection.query.return_value = {
        "ids": [[]],
        "documents": [[]],
        "metadatas": [[]],
        "distances": [[]],
    }

    from waf2.rag.knowledge_base import KnowledgeBase
    import numpy as np

    kb = KnowledgeBase.__new__(KnowledgeBase)
    kb._collection = mock_collection
    kb._info = MagicMock()

    vec = np.zeros(384, dtype=np.float32)
    kb.query(vec, top_k=5, threshold=0.5, domain_filter="generic")

    call_kwargs = mock_collection.query.call_args[1]
    assert call_kwargs["where"] == {"domain": "generic"}


def test_query_no_domain_filter():
    """Verify no where clause when domain_filter is None."""
    mock_collection = MagicMock()
    mock_collection.query.return_value = {
        "ids": [[]],
        "documents": [[]],
        "metadatas": [[]],
        "distances": [[]],
    }

    from waf2.rag.knowledge_base import KnowledgeBase
    import numpy as np

    kb = KnowledgeBase.__new__(KnowledgeBase)
    kb._collection = mock_collection
    kb._info = MagicMock()

    vec = np.zeros(384, dtype=np.float32)
    kb.query(vec, top_k=5, threshold=0.5, domain_filter=None)

    call_kwargs = mock_collection.query.call_args[1]
    assert "where" not in call_kwargs


def test_query_invalid_domain_filter():
    """Verify invalid domain_filter is ignored."""
    mock_collection = MagicMock()
    mock_collection.query.return_value = {
        "ids": [[]],
        "documents": [[]],
        "metadatas": [[]],
        "distances": [[]],
    }

    from waf2.rag.knowledge_base import KnowledgeBase
    import numpy as np

    kb = KnowledgeBase.__new__(KnowledgeBase)
    kb._collection = mock_collection
    kb._info = MagicMock()

    vec = np.zeros(384, dtype=np.float32)
    kb.query(vec, top_k=5, threshold=0.5, domain_filter="invalid")

    call_kwargs = mock_collection.query.call_args[1]
    assert "where" not in call_kwargs


# ---------- RagEngine domain_filter ----------


def test_engine_stores_domain_filter():
    from waf2.rag.engine import RagEngine

    engine = RagEngine(
        embedder=MagicMock(),
        knowledge_base=MagicMock(),
        domain_filter="generic",
    )
    assert engine.domain_filter == "generic"


def test_engine_default_domain_filter():
    from waf2.rag.engine import RagEngine

    engine = RagEngine(
        embedder=MagicMock(),
        knowledge_base=MagicMock(),
    )
    assert engine.domain_filter is None
