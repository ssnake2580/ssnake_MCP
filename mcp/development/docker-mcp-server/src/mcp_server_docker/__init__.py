from .server import app


def main() -> None:
    """Run the server over stdio; the Docker client is opened during lifespan."""
    app.run()


__all__ = ["app", "main"]
