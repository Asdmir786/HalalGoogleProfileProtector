import importlib.metadata

__all__ = ["main"]

try:
    __version__ = importlib.metadata.version("halal-gpp")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"
