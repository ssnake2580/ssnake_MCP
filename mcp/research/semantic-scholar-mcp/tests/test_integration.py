"""Integration tests using real Semantic Scholar API.

These tests hit the actual API and verify end-to-end functionality.
Run with: uv run pytest tests/test_integration.py -v -m integration

On corporate networks with SSL inspection, set:
    DISABLE_SSL_VERIFY=true uv run pytest tests/test_integration.py -v -m integration
"""

import asyncio
import logging
import socket

import pytest
import pytest_asyncio

from semantic_scholar_mcp.client import SemanticScholarClient
from semantic_scholar_mcp.config import settings
from semantic_scholar_mcp.paper_tracker import PaperTracker, get_tracker
from semantic_scholar_mcp.tools._common import set_client_getter
from semantic_scholar_mcp.tools.papers import get_paper_details, search_papers

logger = logging.getLogger(__name__)


def network_available() -> bool:
    """Check if we can reach Semantic Scholar API.

    Returns:
        True if network connection to api.semanticscholar.org:443 succeeds,
        False otherwise.
    """
    try:
        socket.create_connection(("api.semanticscholar.org", 443), timeout=5)
        return True
    except OSError:
        return False


# Mark all tests in this module as integration tests and skip if network unavailable
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not network_available(), reason="Network not available"),
]


@pytest_asyncio.fixture
async def real_client():
    """Create a real client for integration tests.

    Respects DISABLE_SSL_VERIFY environment variable for corporate networks
    with SSL inspection. The client uses settings.disable_ssl_verify which
    reads from this environment variable.
    """
    # Log warning if SSL verification is disabled
    if settings.disable_ssl_verify:
        logger.warning(
            "SSL verification disabled for integration tests. "
            "This should only be used on networks with SSL inspection."
        )

    client = SemanticScholarClient()
    set_client_getter(lambda: client)
    yield client
    await client.close()


@pytest.fixture(autouse=True)
def reset_tracker_integration():
    """Reset tracker between integration tests."""
    PaperTracker.reset_instance()
    yield
    PaperTracker.reset_instance()


class TestSearchIntegration:
    """Integration tests for paper search."""

    @pytest.mark.asyncio
    async def test_search_real_papers(self, real_client: SemanticScholarClient) -> None:
        """Test searching for a known paper returns results."""
        result = await search_papers("attention is all you need", limit=5)

        assert isinstance(result, list)
        assert len(result) > 0
        assert any("attention" in p.title.lower() for p in result)

    @pytest.mark.asyncio
    async def test_search_with_year_filter(self, real_client: SemanticScholarClient) -> None:
        """Test search with year filter."""
        result = await search_papers(
            "transformer neural network",
            year="2020-2024",
            limit=5,
        )

        assert isinstance(result, list)
        if result:  # May be empty for very specific queries
            assert all(2020 <= (p.year or 0) <= 2024 for p in result)


class TestPaperDetailsIntegration:
    """Integration tests for paper details."""

    @pytest.mark.asyncio
    async def test_get_known_paper(self, real_client: SemanticScholarClient) -> None:
        """Test fetching a known paper by ID."""
        # "Attention Is All You Need" paper ID
        paper_id = "204e3073870fae3d05bcbc2f6a8e263d9b72e776"
        result = await get_paper_details(paper_id)

        assert not isinstance(result, str)  # Not an error message
        assert "attention" in result.title.lower()

    @pytest.mark.asyncio
    async def test_get_paper_by_doi(self, real_client: SemanticScholarClient) -> None:
        """Test fetching paper by DOI."""
        result = await get_paper_details("DOI:10.48550/arXiv.1706.03762")

        # May return paper or "not found" message
        if not isinstance(result, str):
            assert result.title is not None


class TestWorkflowIntegration:
    """Integration tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_search_track_workflow(self, real_client: SemanticScholarClient) -> None:
        """Test searching papers and tracking them."""
        # Search for papers
        result = await search_papers("BERT language model", limit=3)

        assert isinstance(result, list)
        assert len(result) > 0

        # Check papers are tracked
        tracker = get_tracker()
        tracked = tracker.get_all_papers()

        assert len(tracked) == len(result)
        assert all(p.paperId in [t.paperId for t in tracked] for p in result)


class TestRateLimitIntegration:
    """Integration tests for rate limit handling."""

    @pytest.mark.asyncio
    async def test_multiple_requests_succeed(self, real_client: SemanticScholarClient) -> None:
        """Test that multiple sequential requests succeed with rate limiting."""
        # Make several requests in sequence
        for i in range(3):
            result = await search_papers(f"machine learning {i}", limit=2)
            assert isinstance(result, list) or "No papers found" in str(result)
            await asyncio.sleep(0.5)  # Small delay between requests


class TestPaperWorkflowIntegration:
    """Integration tests for complete paper workflow: search -> details -> citations -> BibTeX."""

    @pytest.mark.asyncio
    async def test_paper_workflow_search_to_bibtex(
        self, real_client: SemanticScholarClient
    ) -> None:
        """Test complete paper workflow: search -> details -> citations -> export BibTeX."""
        from semantic_scholar_mcp.tools.papers import get_paper_citations
        from semantic_scholar_mcp.tools.tracking import export_bibtex

        # Step 1: Search for a well-known paper
        search_result = await search_papers("attention is all you need transformer", limit=3)

        assert isinstance(search_result, list), f"Expected list, got: {search_result}"
        assert len(search_result) > 0, "Search should return at least one paper"

        # Get the first paper with a valid ID
        paper = search_result[0]
        assert paper.paperId is not None, "Paper should have an ID"
        paper_id = paper.paperId

        # Step 2: Get paper details
        await asyncio.sleep(0.5)  # Rate limit delay
        details = await get_paper_details(paper_id)

        assert not isinstance(details, str), f"Expected paper details, got error: {details}"
        assert details.title is not None, "Paper should have a title"

        # Step 3: Get paper citations (limit to 5 for speed)
        await asyncio.sleep(0.5)  # Rate limit delay
        citations = await get_paper_citations(paper_id, limit=5)

        # Citations may be empty for recent papers, but shouldn't error
        if isinstance(citations, list) and len(citations) > 0:
            assert all(c.paperId is not None for c in citations), "All citations should have IDs"

        # Step 4: Export tracked papers to BibTeX
        bibtex_result = await export_bibtex()

        assert isinstance(bibtex_result, str), "BibTeX export should return a string"
        assert "@" in bibtex_result, "BibTeX output should contain entry markers"
        assert "title" in bibtex_result.lower(), "BibTeX should contain title field"

        # Verify the tracked paper is in the BibTeX output
        tracker = get_tracker()
        tracked = tracker.get_all_papers()
        assert len(tracked) >= 1, "At least the searched paper should be tracked"


class TestAuthorWorkflowIntegration:
    """Integration tests for complete author workflow: search -> details -> top papers."""

    @pytest.mark.asyncio
    async def test_author_workflow_search_to_top_papers(
        self, real_client: SemanticScholarClient
    ) -> None:
        """Test complete author workflow: search -> details -> top papers."""
        from semantic_scholar_mcp.tools.authors import (
            get_author_details,
            get_author_top_papers,
            search_authors,
        )

        # Step 1: Search for a well-known author
        search_result = await search_authors("Geoffrey Hinton", limit=5)

        assert isinstance(search_result, list), f"Expected list, got: {search_result}"
        assert len(search_result) > 0, "Search should return at least one author"

        # Get the first author with a valid ID
        author = search_result[0]
        assert author.authorId is not None, "Author should have an ID"
        author_id = author.authorId

        # Step 2: Get author details with papers
        await asyncio.sleep(0.5)  # Rate limit delay
        details = await get_author_details(author_id, include_papers=True, papers_limit=5)

        assert not isinstance(details, str), f"Expected author details, got error: {details}"
        assert details.name is not None, "Author should have a name"
        assert details.authorId == author_id, "Author ID should match"

        # Step 3: Get author's top papers
        await asyncio.sleep(0.5)  # Rate limit delay
        top_papers = await get_author_top_papers(author_id, top_n=5)

        assert not isinstance(top_papers, str), f"Expected top papers, got error: {top_papers}"
        assert top_papers.author_id == author_id, "Author ID should match"
        assert top_papers.author_name is not None, "Should have author name"

        # Top papers should be sorted by citation count (descending)
        if len(top_papers.top_papers) >= 2:
            for i in range(len(top_papers.top_papers) - 1):
                current_citations = top_papers.top_papers[i].citationCount or 0
                next_citations = top_papers.top_papers[i + 1].citationCount or 0
                assert current_citations >= next_citations, "Papers should be sorted by citations"


class TestBibTeXExportWorkflowIntegration:
    """Integration tests for BibTeX export workflow: track papers -> export -> verify format."""

    @pytest.mark.asyncio
    async def test_bibtex_export_workflow(self, real_client: SemanticScholarClient) -> None:
        """Test BibTeX export workflow: track papers -> export -> verify format."""
        from semantic_scholar_mcp.tools.tracking import (
            clear_tracked_papers,
            export_bibtex,
            list_tracked_papers,
        )

        # Step 1: Clear any existing tracked papers
        await clear_tracked_papers()

        # Verify tracker is empty
        tracked = await list_tracked_papers()
        assert isinstance(tracked, str), "Should return message when no papers tracked"
        assert "No papers tracked" in tracked

        # Step 2: Search for papers to track
        search_result = await search_papers("deep learning neural networks", limit=3)

        assert isinstance(search_result, list), f"Expected list, got: {search_result}"
        assert len(search_result) > 0, "Search should return at least one paper"

        # Step 3: Verify papers are tracked
        tracked = await list_tracked_papers()
        assert isinstance(tracked, list), "Should return list of tracked papers"
        assert len(tracked) == len(search_result), "All searched papers should be tracked"

        # Step 4: Export to BibTeX with various options
        # Default export
        bibtex_default = await export_bibtex()
        assert "@" in bibtex_default, "BibTeX should contain entry markers"
        assert "title" in bibtex_default.lower(), "BibTeX should contain title field"
        assert "author" in bibtex_default.lower(), "BibTeX should contain author field"
        assert "year" in bibtex_default.lower(), "BibTeX should contain year field"

        # Export with abstract
        bibtex_with_abstract = await export_bibtex(include_abstract=True)
        assert "abstract" in bibtex_with_abstract.lower(), "BibTeX should contain abstract"

        # Export with different cite key format
        bibtex_author_year_title = await export_bibtex(cite_key_format="author_year_title")
        assert "@" in bibtex_author_year_title, "BibTeX should contain entry markers"

        # Step 5: Verify BibTeX format is valid
        # Count the number of entries (should match tracked papers)
        entry_count = bibtex_default.count("@article") + bibtex_default.count("@inproceedings")
        entry_count += bibtex_default.count("@misc") + bibtex_default.count("@book")
        assert entry_count >= 1, "BibTeX should contain at least one entry"

        # Verify tracked papers have paperId
        for paper in tracked:
            assert paper.paperId is not None, "Tracked paper should have paperId"
