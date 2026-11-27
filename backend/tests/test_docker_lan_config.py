"""Offline static contract tests for Dockerfiles, .dockerignore, compose.yaml, and Nginx proxy (docker-lan-v1.md §8)."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DOCKERFILE = ROOT / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT / "etis-frontend" / "Dockerfile"
ROOT_DOCKERIGNORE = ROOT / ".dockerignore"
FRONTEND_DOCKERIGNORE = ROOT / "etis-frontend" / ".dockerignore"
COMPOSE_FILE = ROOT / "compose.yaml"
NGINX_CONF = ROOT / "docker" / "nginx-lan.conf"

PINNED_FROM_RE = re.compile(
    r"^FROM\s+([a-z0-9._/-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9._-]+)?)@sha256:([0-9a-f]{64}|TO_VERIFY_[a-z0-9_]+)(?:\s+AS\s+[a-zA-Z0-9_-]+)?$"
)
PINNED_IMAGE_RE = re.compile(
    r"^([a-z0-9._/-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9._-]+)?)@sha256:([0-9a-f]{64}|TO_VERIFY_[a-z0-9_]+)$"
)
EXPECTED_TO_VERIFY_PLACEHOLDERS = {
    "TO_VERIFY_python",
    "TO_VERIFY_node",
    "TO_VERIFY_postgres",
    "TO_VERIFY_nginx_unprivileged",
}
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


def _load_compose() -> dict:
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("dockerfile_path", [BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE])
def test_dockerfile_from_instructions_pin_exact_version_and_digest_or_to_verify(dockerfile_path: Path) -> None:
    lines = _logical_dockerfile_lines(dockerfile_path)
    from_lines = [line for line in lines if line.upper().startswith("FROM ")]
    assert from_lines, f"No FROM instructions found in {dockerfile_path}"
    for line in from_lines:
        match = PINNED_FROM_RE.match(line)
        assert match is not None, (
            f"FROM instruction in {dockerfile_path.name} must pin exact tag and @sha256:(<64 hex>|TO_VERIFY_*): {line}"
        )
        version_tag = match.group(2)
        assert "latest" not in version_tag.lower()


def test_all_image_digests_are_valid_hex_or_to_verify_and_list_step5_blockers() -> None:
    """Reject malformed/invented digests and enumerate all TO_VERIFY_* placeholders blocking step 5."""
    to_verify_entries: list[str] = []

    for dockerfile_path in (BACKEND_DOCKERFILE, FRONTEND_DOCKERFILE):
        for line in _logical_dockerfile_lines(dockerfile_path):
            if line.upper().startswith("FROM "):
                match = PINNED_FROM_RE.match(line)
                assert match is not None, f"Invalid FROM digest in {dockerfile_path}: {line}"
                digest = match.group(3)
                assert re.fullmatch(r"[0-9a-f]{64}|TO_VERIFY_[a-z0-9_]+", digest)
                if digest.startswith("TO_VERIFY_"):
                    to_verify_entries.append(f"{dockerfile_path.name}: {match.group(1)}:{match.group(2)}@sha256:{digest}")

    spec = _load_compose()
    for svc_name, svc in spec["services"].items():
        if "build" in svc:
            continue
        image = svc.get("image", "")
        match = PINNED_IMAGE_RE.match(image)
        assert match is not None, f"Invalid external image digest on service {svc_name}: {image}"
        digest = match.group(3)
        assert re.fullmatch(r"[0-9a-f]{64}|TO_VERIFY_[a-z0-9_]+", digest)
        if digest.startswith("TO_VERIFY_"):
            to_verify_entries.append(f"compose.yaml ({svc_name}): {image}")

    found_placeholders = {entry.split("@sha256:", 1)[1] for entry in to_verify_entries}
    assert found_placeholders == EXPECTED_TO_VERIFY_PLACEHOLDERS, (
        f"Step 5 TO_VERIFY digest placeholders mismatch: {to_verify_entries}"
    )


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


def test_compose_external_images_pin_exact_version_and_digest_or_to_verify() -> None:
    spec = _load_compose()
    services = spec["services"]
    for name in ("database", "reverse-proxy"):
        image = services[name]["image"]
        assert PINNED_IMAGE_RE.match(image), f"Service {name} image must pin exact tag + @sha256 digest: {image}"
    assert services["reverse-proxy"]["image"].startswith("nginxinc/nginx-unprivileged:")


def test_compose_ports_and_non_internal_lan_network_isolation() -> None:
    spec = _load_compose()
    services = spec["services"]
    networks = spec["networks"]

    services_with_ports = [name for name, svc in services.items() if "ports" in svc]
    assert services_with_ports == ["reverse-proxy"], (
        f"Exactly one service (reverse-proxy) may have a ports: entry; got {services_with_ports}"
    )
    assert services["reverse-proxy"]["ports"] == ["${ETIS_LAN_BIND_IP:?Set ETIS_LAN_BIND_IP in .env}:8443:8443"]

    assert networks["etis_db_net"].get("internal") is True
    assert networks["etis_edge_net"].get("internal") is True
    assert "etis_lan_net" in networks
    assert not networks["etis_lan_net"].get("internal", False), "etis_lan_net must be non-internal to publish 8443"

    proxy_nets = services["reverse-proxy"]["networks"]
    assert any(not networks[n].get("internal", False) for n in proxy_nets), (
        "reverse-proxy must be attached to a non-internal network so port 8443 is published"
    )
    assert "etis_lan_net" in proxy_nets and "etis_edge_net" in proxy_nets

    for isolated_svc in ("api", "web", "database", "migrate"):
        svc_nets = services[isolated_svc].get("networks", [])
        assert svc_nets, f"{isolated_svc} must specify networks explicitly"
        for net_name in svc_nets:
            assert networks[net_name].get("internal") is True, (
                f"{isolated_svc} must not attach to non-internal network {net_name}"
            )
            assert net_name != "etis_lan_net"


def test_compose_services_enforce_non_root_read_only_cap_drop_and_tmpfs() -> None:
    spec = _load_compose()
    services = spec["services"]
    expected_services = {"database", "migrate", "api", "worker", "web", "reverse-proxy"}
    assert set(services.keys()) == expected_services

    for name, svc in services.items():
        assert svc.get("read_only") is True, f"{name} must set read_only: true"
        assert "no-new-privileges:true" in svc.get("security_opt", []), f"{name} missing no-new-privileges:true"
        assert svc.get("cap_drop") == ["ALL"], f"{name} must drop ALL capabilities"

        user_spec = str(svc.get("user", ""))
        assert user_spec and ":" in user_spec, f"{name} must set explicit non-root UID:GID"
        uid, gid = user_spec.split(":", 1)
        assert uid not in {"0", "root"} and gid not in {"0", "root"}, f"{name} must not run as root"

        tmpfs_entries = svc.get("tmpfs", [])
        assert any(entry.startswith("/tmp:") for entry in tmpfs_entries), f"{name} must mount /tmp as tmpfs"
        for entry in tmpfs_entries:
            for opt in ("noexec", "nosuid", "nodev"):
                assert opt in entry, f"{name} tmpfs {entry!r} missing {opt}"


def test_compose_long_running_services_define_healthchecks_and_nginx_unprivileged_pid() -> None:
    spec = _load_compose()
    services = spec["services"]
    for name in ("database", "api", "worker", "web", "reverse-proxy"):
        hc = services[name].get("healthcheck")
        assert isinstance(hc, dict) and hc.get("test"), f"Service {name} must define a healthcheck"

    proxy_hc_cmd = " ".join(services["reverse-proxy"]["healthcheck"]["test"])
    assert "/tmp/nginx.pid" in proxy_hc_cmd, "nginx-unprivileged writes its PID to /tmp/nginx.pid"
    assert "/var/run/nginx.pid" not in proxy_hc_cmd
    assert "curl" not in proxy_hc_cmd and "wget" not in proxy_hc_cmd

    # Q2: feed worker must be behind opt-in profile "feeds"
    assert services["worker"].get("profiles") == ["feeds"]
    # migrate must run --db-only so it never writes .env inside a read_only container
    assert services["migrate"]["command"] == ["python", "scripts/initialize.py", "--db-only"]


def test_compose_database_named_volume_and_ro_bind_mounts() -> None:
    spec = _load_compose()
    services = spec["services"]

    assert "etis_pgdata" in spec.get("volumes", {})
    assert services["database"]["volumes"] == ["etis_pgdata:/var/lib/postgresql/data"]
    assert services["database"]["networks"] == ["etis_db_net"]

    # Q3 & §3.2: all bind mounts on migrate, api, and reverse-proxy must be read-only (:ro)
    for name in ("migrate", "api", "reverse-proxy"):
        for mount in services[name].get("volumes", []):
            assert mount.endswith(":ro"), f"Bind mount on {name} must be read-only (:ro): {mount}"

    api_mounts = services["api"]["volumes"]
    assert "./data/external/public_suffix_list.dat:/app/data/external/public_suffix_list.dat:ro" in api_mounts
    assert "./ml/models/deployed_char.joblib:/app/ml/models/deployed_char.joblib:ro" in api_mounts
    assert "./ml/models/url_host_v3.joblib:/app/ml/models/url_host_v3.joblib:ro" in api_mounts


def test_compose_least_privilege_secret_distribution() -> None:
    spec = _load_compose()
    services = spec["services"]

    web_env = services["web"].get("environment", {})
    for forbidden_in_web in (
        "DATABASE_URL",
        "ETIS_DB_PASSWORD",
        "ETIS_SERVER_REF_KEY",
        "ETIS_HOST_PSEUDONYM_KEY",
        "ETIS_MALWARE_PSEUDONYM_KEY",
        "ETIS_STIX_NAMESPACE",
    ):
        assert forbidden_in_web not in web_env, f"web must not receive {forbidden_in_web}"
        for val in web_env.values():
            assert forbidden_in_web not in str(val)

    assert "environment" not in services["reverse-proxy"], "reverse-proxy must not receive any secret env vars"

    db_env = services["database"].get("environment", {})
    for forbidden_in_db in ("ETIS_API_KEY", "ETIS_SERVER_REF_KEY", "ETIS_HOST_PSEUDONYM_KEY"):
        assert forbidden_in_db not in db_env


def test_nginx_lan_conf_enforces_tls_routing_and_blocks_extension_endpoints() -> None:
    text = NGINX_CONF.read_text(encoding="utf-8")
    assert "listen 8443 ssl;" in text
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in text
    assert "access_log off;" in text
    assert "location ^~ /extension/v1" in text and "return 404;" in text
    assert "location ^~ /agent/v1/" in text
    assert "proxy_pass http://api:8000/agent/v1/;" in text
    assert 'proxy_set_header X-API-Key "";' in text
    assert 'proxy_set_header Cookie "";' in text
    assert "client_max_body_size 512k;" in text
    assert "proxy_pass http://web:5173;" in text
