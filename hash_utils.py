"""SHA-256 fingerprinting for the monitored file."""
import hashlib
from pathlib import Path


def sha256_file(path, chunk_size=65536):
    """Return the hex SHA-256 of a file, streamed in chunks so file size doesn't matter."""
    digest = hashlib.sha256()
    with open(Path(path), "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "target_system/config.json"
    print(sha256_file(target), target)
