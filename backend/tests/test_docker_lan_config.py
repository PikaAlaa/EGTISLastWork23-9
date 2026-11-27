"""Offline static contract tests for Dockerfiles and .dockerignore (docs/design/docker-lan-v1.md §8.1)."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DOCKERFILE = ROOT / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT / "etis-frontend" / "Dockerfile"
ROOT_DOCKERIGNORE = ROOT / ".dockerignore"
FRONTEND_DOCKERIGNORE = ROOT / "etis-frontend" / ".dockerignore"

PINNED_FROM_RE = re.compile(
    r"^FROM\s+([a-z0-9._/-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9._-]+)?)@sha256:([0-9a-f]{64})(?:\s+AS\s+[a-zA-Z0-9_-]+)?$"
)
FORBIDDEN_COPY_TOKENS = (
    ".env",
    "ml/models",
    "ml/data",
    "data/external",
    "data/raw",
    "data/processed",
    "data/private",
    "evaluation",
    "var",
    "release-artifacts",
    "colab-bundle",
)
SECRET_ENV_NAMES = (
    "ETIS_API_KEY",
    "ETIS_DB_PASSWORD",
    "ETIS_HOST_PSEUDONYM_KEY",
    "ETIS_MALWARE_PSEUDONYM_KEY",
    "ETIS_SERVER_REF_KEY",
    "ETIS_STIX_NAMESPACE",
    "POSTGRES_PASSWORD",
)


def _logical_dockerfile_lines(path: Path) -> list[str]:
    """Join backslash-continued lines and strip comments."""
    lines: list[str] = []
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1].strip() + " "
        else:
            current += stripped
            lines.append(current.strip())
            current = ""
    if current:
        lines.append(current.strip())
    return lines


def _dockerignore_patterns(path: Path) -> list[str]:
    return [
        line.strip().rstrip("/")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _matches_dockerignore(candidate: str, patterns: list[str]) -> bool:
    norm = candidate.strip("/")
    parts = norm.split("/")
    for pattern in patterns:
        if pattern.startswith("!"):
            continue
        if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(parts[0], pattern) or fnmatch.fnmatch(parts[-1], pattern):
            return True
        if norm.startswith(pattern + "/"):
            return True
    return False


@pytest.mark.parametrize("dockerfile_path", [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE])
def test_dockerfile_from_instructions_pin_exact_version_and_sha256_digest(dockerfile_path: Path) -> None:
    lines = _logical_dockerfile_lines(dockerfile_path)
    from_lines = [line for line in lines if line.upper().startswith("FROM ")]
    assert from_lines, f"No FROM instructions found in {dockerfile_path}"
    for line in from_lines:
        match = PINNED_FROM_RE.match(line)
        assert match is not None, f"Unpinned or floating FROM instruction in {dockerfile_path.name}: {line}"
        version_tag = match.group(2)
        assert "latest" not in version_tag.lower()


@pytest.mark.parametrize("dockerfile_path", [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE])
def test_dockerfile_final_stage_runs_as_non_root_and_defines_healthcheck(dockerfile_path: Path) -> None:
    lines = _logical_dockerfile_lines(dockerfile_path)
    last_from_idx = max(idx for idx, line in enumerate(lines) if line.upper().startswith("FROM "))
    final_stage = lines[last_from_idx:]

    user_lines = [(idx, line) for idx, line in enumerate(final_stage) if line.upper().startswith("USER ")]
    cmd_lines = [
        (idx, line)
        for idx, line in enumerate(final_stage)
        if line.upper().startswith("CMD ") or line.upper().startswith("ENTRYPOINT ")
    ]
    healthcheck_lines = [line for line in final_stage if line.upper().startswith("HEALTHCHECK ")]

    assert user_lines, f"Missing USER instruction in final stage of {dockerfile_path}"
    assert cmd_lines, f"Missing CMD/ENTRYPOINT in final stage of {dockerfile_path}"
    assert healthcheck_lines, f"Missing HEALTHCHECK in final stage of {dockerfile_path}"

    user_idx, user_line = user_lines[-1]
    cmd_idx, _ = cmd_lines[0]
    assert user_idx < cmd_idx, f"USER must appear before CMD/ENTRYPOINT in {dockerfile_path}"

    user_spec = user_line.split(None, 1)[1].strip()
    assert user_spec not in {"root", "0", "0:0", "root:root"}, f"Root USER forbidden: {user_spec}"
    for part in user_spec.split(":"):
        assert part != "0" and part != "root"


@pytest.mark.parametrize("dockerfile_path", [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE])
def test_dockerfile_never_copies_models_datasets_or_defines_secret_env(dockerfile_path: Path) -> None:
    lines = _logical_dockerfile_lines(dockerfile_path)
    for line in lines:
        upper = line.upper()
        if upper.startswith("COPY ") or upper.startswith("ADD "):
            for forbidden in FORBIDDEN_COPY_TOKENS:
                assert forbidden not in line, (
                    f"{dockerfile_path.name} must never copy {forbidden!r} into the image: {line}"
                )
        if upper.startswith("ENV ") or upper.startswith("ARG "):
            for secret_name in SECRET_ENV_NAMES:
                assert secret_name not in line, (
                    f"{dockerfile_path.name} must never declare secret {secret_name} in ENV/ARG: {line}"
                )


def test_root_dockerignore_excludes_all_forbidden_artifacts() -> None:
    patterns = _dockerignore_patterns(ROOT_DOCKERIGNORE)
    required_excluded_samples = [
        ".git",
        ".env",
        ".env.local",
        ".env.production",
        ".venv",
        "var/etis.db",
        "scan.db",
        "local.sqlite3",
        "server.log",
        "var/certs/lan-server.key",
        "var/certs/lan-server.crt",
        "cert.pem",
        "ml/models/deployed_char.joblib",
        "ml/models/url_host_v3.joblib",
        "ml/data/tokenizer.pkl",
        "data/models/candidate.joblib",
        "data/external/public_suffix_list.dat",
        "data/external/attack/enterprise-attack.json",
        "data/raw/sample.csv",
        "data/processed/train.parquet",
        "data/private/real.csv",
        "evaluation/FREEZE.json",
        "evaluation/reports/2026-10-v3/public_suffix_list.dat",
        "release-artifacts/bundle.zip",
        "colab-bundle/train.zip",
        "backend/tests/test_docker_lan_config.py",
        "docs/design/docker-lan-v1.md",
    ]
    for sample in required_excluded_samples:
        assert _matches_dockerignore(sample, patterns), (
            f".dockerignore failed to exclude forbidden path {sample!r}"
        )


def test_frontend_dockerignore_excludes_secrets_and_build_outputs() -> None:
    patterns = _dockerignore_patterns(FRONTEND_DOCKERIGNORE)
    for sample in ("node_modules", "dist", ".env", ".env.local", "lan-server.key", "lan-server.crt", "debug.log"):
        assert _matches_dockerignore(sample, patterns), (
            f"etis-frontend/.dockerignore failed to exclude {sample!r}"
        )
