"""Validate the Docker setup without needing Docker installed.

A failed image build costs several minutes before it tells you which file was
missing. Most of those failures are knowable up front: a COPY source that is
excluded by .dockerignore, a script the entrypoint needs that never made it
into the context, or an environment variable shadowed by Compose precedence.

This checks those statically so the first real build is not the thing that
discovers them.

    python -m scripts.check_docker
"""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
COMPOSE = ROOT / "docker-compose.yml"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((bool(ok), name, detail))


def load_dockerignore(context: Path) -> list[str]:
    path = context / ".dockerignore"
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def is_ignored(relative: str, patterns: list[str]) -> bool:
    """Approximate Docker's exclusion matching for the checks below."""
    parts = Path(relative).parts
    for pattern in patterns:
        pattern = pattern.rstrip("/")
        if fnmatch.fnmatch(relative, pattern):
            return True
        # A bare directory name excludes everything beneath it.
        if pattern in parts:
            return True
    return False


def copied_sources(dockerfile: Path) -> list[str]:
    """COPY sources, skipping --from=stage copies (those come from an earlier
    build stage, not the host context)."""
    sources: list[str] = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        if "--from=" in stripped:
            continue
        tokens = [t for t in stripped.split()[1:] if not t.startswith("--")]
        sources.extend(tokens[:-1])  # last token is the destination
    return sources


def check_context(name: str, context: Path) -> None:
    dockerfile = context / "Dockerfile"
    check(dockerfile.exists(), f"{name}: Dockerfile present")
    if not dockerfile.exists():
        return

    patterns = load_dockerignore(context)
    check(bool(patterns), f"{name}: .dockerignore present", "no .dockerignore")

    for source in copied_sources(dockerfile):
        if any(ch in source for ch in "*?["):
            continue  # globs may legitimately match nothing
        path = context / source
        check(path.exists(), f"{name}: COPY source exists -> {source}")
        if path.exists():
            check(
                not is_ignored(source, patterns),
                f"{name}: COPY source not excluded by .dockerignore -> {source}",
            )

    # Secrets and local state must never be baked into an image layer.
    for leak in (".env", "sentinelcti.db", "var", "node_modules"):
        if (context / leak).exists():
            check(
                is_ignored(leak, patterns),
                f"{name}: '{leak}' excluded from the build context",
                "would be copied into the image",
            )


def check_compose() -> None:
    check(COMPOSE.exists(), "compose file present")
    if not COMPOSE.exists():
        return
    text = COMPOSE.read_text(encoding="utf-8")

    try:
        import yaml
    except ImportError:
        check(True, "compose parses (skipped, pyyaml not installed)")
        return

    try:
        data = yaml.safe_load(text)
        check(True, "compose parses as YAML")
    except Exception as exc:  # noqa: BLE001
        check(False, "compose parses as YAML", str(exc)[:80])
        return

    services = data.get("services", {})
    check("backend" in services and "frontend" in services, "compose defines backend + frontend")

    backend = services.get("backend", {})
    env = backend.get("environment", {}) or {}
    env_keys = set(env) if isinstance(env, dict) else {e.split("=")[0] for e in env}

    # Compose precedence is environment > env_file > Dockerfile ENV. Naming
    # DATABASE_URL under `environment` would silently override backend/.env and
    # run on SQLite with a Supabase URL configured.
    check(
        "DATABASE_URL" not in env_keys,
        "compose does not shadow DATABASE_URL from env_file",
        "environment: overrides env_file:, so backend/.env would be ignored",
    )

    check(bool(backend.get("env_file")), "backend reads backend/.env via env_file")

    ports = backend.get("ports", []) or []
    check(
        all(str(p).startswith("127.0.0.1:") for p in ports),
        "backend port published on loopback only",
        f"{ports} - the API has no authentication",
    )

    # The SQLite fallback has to live in the Dockerfile ENV for the precedence
    # above to work out.
    dockerfile = (BACKEND / "Dockerfile").read_text(encoding="utf-8")
    check(
        re.search(r"ENV\s+DATABASE_URL=", dockerfile) is not None,
        "backend Dockerfile provides the DATABASE_URL fallback",
    )


def check_runtime_expectations() -> None:
    """Files the containers need at runtime, not just at build time."""
    check((FRONTEND / "nginx.conf").exists(), "frontend nginx.conf present")
    if (FRONTEND / "nginx.conf").exists():
        conf = (FRONTEND / "nginx.conf").read_text(encoding="utf-8")
        check("proxy_pass http://backend:8000" in conf, "nginx proxies /api to the backend service")
        check("try_files" in conf, "nginx has an SPA fallback for client-side routes")
        check("client_max_body_size" in conf, "nginx allows uploads through to the backend limit")

    check((BACKEND / "requirements.txt").exists(), "backend requirements.txt present")
    check((BACKEND / "scripts" / "seed.py").exists(), "seed script in the image (used via exec)")


def main() -> int:
    check_context("backend", BACKEND)
    check_context("frontend", FRONTEND)
    check_compose()
    check_runtime_expectations()

    print("=" * 68)
    print("DOCKER PREFLIGHT")
    print("=" * 68)
    failed = [r for r in results if not r[0]]
    for ok, name, detail in results:
        if not ok:
            print(f"  FAIL  {name}")
            if detail:
                print(f"        {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print(f"{len(failed)} problem(s) would break or compromise the build.")
        return 1
    print("Build context looks correct. Run: docker compose up --build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
