"""Tests for error propagation from client through tools.

This module tests that exceptions raised by the client layer are properly
propagated through the tool layer with their attributes intact.
"""

from unittest.mock import AsyncMock, patch

import pytest

from semantic_scholar_mcp.exceptions import (
    APIConnectionError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
)
from semantic_scholar_mcp.tools.papers import get_paper_details, search_papers


class TestRateLimitErrorPropagation:
    """Tests for RateLimitError propagation through the tool layer."""

    @pytest.mark.asyncio
    async def test_rate_limit_error_propagates_with_retry_after(self) -> None:
        """Test that RateLimitError propagates with retry_after attribute."""
        expected_retry_after = 60.0
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=RateLimitError(
                "Rate limit exceeded for /paper/search",
                retry_after=expected_retry_after,
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(RateLimitError) as exc_info:
                await search_papers("test query")

            assert exc_info.value.retry_after == expected_retry_after
            assert "Rate limit exceeded" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_rate_limit_error_propagates_without_retry_after(self) -> None:
        """Test that RateLimitError propagates when retry_after is None."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=RateLimitError(
                "Rate limit exceeded for /paper/search",
                retry_after=None,
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(RateLimitError) as exc_info:
                await search_papers("test query")

            assert exc_info.value.retry_after is None


class TestNotFoundErrorPropagation:
    """Tests for NotFoundError propagation through the tool layer."""

    @pytest.mark.asyncio
    async def test_not_found_error_returns_informative_message_in_get_paper_details(
        self,
    ) -> None:
        """Test that NotFoundError in get_paper_details returns informative message."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=NotFoundError("Resource not found: /paper/nonexistent-id")
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            result = await get_paper_details("nonexistent-id")

            # get_paper_details catches NotFoundError and returns a message
            assert isinstance(result, str)
            assert "not found" in result.lower()
            assert "nonexistent-id" in result

    @pytest.mark.asyncio
    async def test_not_found_error_contains_original_message(self) -> None:
        """Test that NotFoundError contains the original error message."""
        original_message = (
            "Resource not found: /paper/abc123. For DOIs, use format 'DOI:10.xxxx/xxxxx'."
        )
        error = NotFoundError(original_message)

        assert str(error) == original_message


class TestServerErrorPropagation:
    """Tests for ServerError propagation through the tool layer."""

    @pytest.mark.asyncio
    async def test_server_error_propagates_with_status_code(self) -> None:
        """Test that ServerError propagates with status_code attribute."""
        expected_status_code = 503
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=ServerError(
                f"Semantic Scholar API server error ({expected_status_code}) for /paper/search",
                status_code=expected_status_code,
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(ServerError) as exc_info:
                await search_papers("test query")

            assert exc_info.value.status_code == expected_status_code
            assert "503" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_server_error_500_propagates(self) -> None:
        """Test that HTTP 500 ServerError propagates correctly."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=ServerError(
                "Semantic Scholar API server error (500) for /paper/search",
                status_code=500,
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(ServerError) as exc_info:
                await search_papers("test query")

            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_server_error_502_propagates(self) -> None:
        """Test that HTTP 502 ServerError propagates correctly."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=ServerError(
                "Semantic Scholar API server error (502) for /paper/search",
                status_code=502,
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(ServerError) as exc_info:
                await search_papers("test query")

            assert exc_info.value.status_code == 502


class TestAuthenticationErrorPropagation:
    """Tests for AuthenticationError propagation through the tool layer."""

    @pytest.mark.asyncio
    async def test_authentication_error_propagates_in_search(self) -> None:
        """Test that AuthenticationError propagates in search_papers."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=AuthenticationError(
                "Authentication failed for /paper/search. Please verify your API key is valid."
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(AuthenticationError) as exc_info:
                await search_papers("test query")

            assert "Authentication failed" in str(exc_info.value)
            assert "API key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authentication_error_propagates_in_get_paper_details(self) -> None:
        """Test that AuthenticationError propagates in get_paper_details."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=AuthenticationError(
                "Authentication failed for /paper/12345. Please verify your API key is valid."
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(AuthenticationError) as exc_info:
                await get_paper_details("12345")

            assert "Authentication failed" in str(exc_info.value)


class TestAPIConnectionErrorPropagation:
    """Tests for APIConnectionError propagation through the tool layer."""

    @pytest.mark.asyncio
    async def test_connection_error_propagates_in_search(self) -> None:
        """Test that APIConnectionError propagates in search_papers."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=APIConnectionError("Failed to connect to Semantic Scholar API")
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(APIConnectionError) as exc_info:
                await search_papers("test query")

            assert "Failed to connect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_error_propagates_in_get_paper_details(self) -> None:
        """Test that APIConnectionError propagates in get_paper_details."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(side_effect=APIConnectionError("Request timed out"))

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(APIConnectionError) as exc_info:
                await get_paper_details("12345")

            assert "timed out" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_circuit_breaker_error_propagates_as_connection_error(self) -> None:
        """Test that circuit breaker errors propagate as APIConnectionError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=APIConnectionError(
                "Service temporarily unavailable. The circuit breaker is open "
                "due to repeated failures."
            )
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(APIConnectionError) as exc_info:
                await search_papers("test query")

            assert "circuit breaker" in str(exc_info.value).lower()


class TestSearchPapersErrorHandling:
    """Tests for error handling in the search_papers tool function."""

    @pytest.mark.asyncio
    async def test_search_papers_propagates_rate_limit_error(self) -> None:
        """Test that search_papers propagates RateLimitError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=RateLimitError("Rate limit exceeded", retry_after=30.0)
        )

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(RateLimitError),
        ):
            await search_papers("neural networks")

    @pytest.mark.asyncio
    async def test_search_papers_propagates_server_error(self) -> None:
        """Test that search_papers propagates ServerError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=ServerError("Server error", status_code=500)
        )

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(ServerError),
        ):
            await search_papers("neural networks")

    @pytest.mark.asyncio
    async def test_search_papers_propagates_authentication_error(self) -> None:
        """Test that search_papers propagates AuthenticationError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=AuthenticationError("Authentication failed")
        )

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(AuthenticationError),
        ):
            await search_papers("neural networks")

    @pytest.mark.asyncio
    async def test_search_papers_propagates_connection_error(self) -> None:
        """Test that search_papers propagates APIConnectionError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(side_effect=APIConnectionError("Connection failed"))

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(APIConnectionError),
        ):
            await search_papers("neural networks")


class TestGetPaperDetailsErrorHandling:
    """Tests for error handling in the get_paper_details tool function."""

    @pytest.mark.asyncio
    async def test_get_paper_details_handles_not_found_gracefully(self) -> None:
        """Test that get_paper_details returns message for NotFoundError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=NotFoundError("Resource not found: /paper/invalid-id")
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            result = await get_paper_details("invalid-id")

            # Should return a string message, not raise an exception
            assert isinstance(result, str)
            assert "invalid-id" in result

    @pytest.mark.asyncio
    async def test_get_paper_details_propagates_rate_limit_error(self) -> None:
        """Test that get_paper_details propagates RateLimitError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=RateLimitError("Rate limit exceeded", retry_after=45.0)
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(RateLimitError) as exc_info:
                await get_paper_details("12345")

            assert exc_info.value.retry_after == 45.0

    @pytest.mark.asyncio
    async def test_get_paper_details_propagates_server_error(self) -> None:
        """Test that get_paper_details propagates ServerError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=ServerError("Server error", status_code=503)
        )

        with patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client):
            with pytest.raises(ServerError) as exc_info:
                await get_paper_details("12345")

            assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_get_paper_details_propagates_authentication_error(self) -> None:
        """Test that get_paper_details propagates AuthenticationError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(side_effect=AuthenticationError("Invalid API key"))

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(AuthenticationError),
        ):
            await get_paper_details("12345")

    @pytest.mark.asyncio
    async def test_get_paper_details_propagates_connection_error(self) -> None:
        """Test that get_paper_details propagates APIConnectionError."""
        mock_client = AsyncMock()
        mock_client.get_with_retry = AsyncMock(
            side_effect=APIConnectionError("Network unreachable")
        )

        with (
            patch("semantic_scholar_mcp.tools.papers.get_client", return_value=mock_client),
            pytest.raises(APIConnectionError),
        ):
            await get_paper_details("12345")


class TestErrorAttributePreservation:
    """Tests that error attributes are preserved through propagation."""

    @pytest.mark.asyncio
    async def test_rate_limit_error_preserves_all_attributes(self) -> None:
        """Test that RateLimitError preserves all attributes after propagation."""
        expected_message = "Rate limit exceeded for /paper/search"
        expected_retry_after = 120.5

        error = RateLimitError(expected_message, retry_after=expected_retry_after)

        assert str(error) == expected_message
        assert error.retry_after == expected_retry_after

    @pytest.mark.asyncio
    async def test_server_error_preserves_all_attributes(self) -> None:
        """Test that ServerError preserves all attributes after propagation."""
        expected_message = "Semantic Scholar API server error (502)"
        expected_status_code = 502

        error = ServerError(expected_message, status_code=expected_status_code)

        assert str(error) == expected_message
        assert error.status_code == expected_status_code

    @pytest.mark.asyncio
    async def test_exception_inheritance_chain(self) -> None:
        """Test that all custom exceptions inherit from SemanticScholarError."""
        from semantic_scholar_mcp.exceptions import SemanticScholarError

        rate_limit_error = RateLimitError("test", retry_after=10.0)
        not_found_error = NotFoundError("test")
        server_error = ServerError("test", status_code=500)
        auth_error = AuthenticationError("test")
        connection_error = APIConnectionError("test")

        assert isinstance(rate_limit_error, SemanticScholarError)
        assert isinstance(not_found_error, SemanticScholarError)
        assert isinstance(server_error, SemanticScholarError)
        assert isinstance(auth_error, SemanticScholarError)
        assert isinstance(connection_error, SemanticScholarError)

        # All should also be Exceptions
        assert isinstance(rate_limit_error, Exception)
        assert isinstance(not_found_error, Exception)
        assert isinstance(server_error, Exception)
        assert isinstance(auth_error, Exception)
        assert isinstance(connection_error, Exception)
