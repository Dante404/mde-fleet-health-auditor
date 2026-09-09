"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .auth import (
    GRAPH_SCOPES,
    MDE_SCOPES,
    AuthenticationError,
    DeviceCodeCredential,
)
from .client import ApiError, GraphHuntingClient, MDEClient, MDE_REGION_URLS
from .hunting import FLEET_ENRICHMENT_QUERY, enrich_devices
from .models import DeviceRecord, SEVERITY_RANK
from .policy import AuditPolicy, PolicyError, audit_devices
from .reporting import build_report, format_summary, write_csv, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mde-health-audit",
        description="Audit Microsoft Defender for Endpoint fleet health without changing devices.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--tenant-id", default=os.getenv("MDE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("MDE_CLIENT_ID"))
    parser.add_argument(
        "--api-region",
        choices=sorted(MDE_REGION_URLS),
        default="global",
        help="MDE API region (default: global)",
    )
    parser.add_argument("--config", type=Path, help="TOML health-policy file")
    parser.add_argument(
        "--machines-file",
        type=Path,
        help="Audit a saved List machines JSON response instead of calling MDE",
    )
    parser.add_argument(
        "--include-hunting",
        action="store_true",
        help="Enrich results through Microsoft Graph advanced hunting",
    )
    parser.add_argument(
        "--hunting-file",
        type=Path,
        help="Use a saved runHuntingQuery response; implies --include-hunting",
    )
    parser.add_argument(
        "--hunting-days",
        type=int,
        default=30,
        help="Advanced hunting lookback from 1 to 30 days (default: 30)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=10_000,
        help="MDE pagination size from 1 to 10000 (default: 10000)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="Report directory (default: reports)",
    )
    parser.add_argument(
        "--output-prefix",
        help="Report filename prefix (default: UTC timestamp)",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json", "both"),
        default="both",
        help="Report format (default: both)",
    )
    parser.add_argument(
        "--all-devices",
        action="store_true",
        help="Include healthy devices instead of findings only",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high"),
        default="none",
        help="Exit 1 if this severity or higher is found (default: none)",
    )
    return parser


def _load_json(path: Path, collection_key: str) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get(collection_key)
    if not isinstance(raw, list):
        raise ValueError(
            f"{path} must contain a JSON array or an object with a '{collection_key}' array"
        )
    return [item for item in raw if isinstance(item, dict)]


def _require_identity(args: argparse.Namespace) -> tuple[str, str]:
    if not args.tenant_id or not args.client_id:
        raise ValueError(
            "--tenant-id and --client-id are required for live API calls "
            "(or set MDE_TENANT_ID and MDE_CLIENT_ID)"
        )
    return args.tenant_id, args.client_id


def _safe_prefix(raw: str | None, now: datetime) -> str:
    value = raw or f"mde-health-audit-{now.strftime('%Y%m%dT%H%M%SZ')}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise ValueError(
            "--output-prefix must contain only letters, digits, dots, underscores, and hyphens"
        )
    return value


def _load_machines(
    args: argparse.Namespace,
    credential: DeviceCodeCredential | None,
) -> tuple[list[dict[str, Any]], str, DeviceCodeCredential | None]:
    if args.machines_file:
        return _load_json(args.machines_file, "value"), str(args.machines_file), credential

    tenant_id, client_id = _require_identity(args)
    credential = credential or DeviceCodeCredential(tenant_id, client_id)
    client = MDEClient(
        lambda: credential.get_token(MDE_SCOPES),
        base_url=MDE_REGION_URLS[args.api_region],
    )
    return client.list_machines(page_size=args.page_size), "Microsoft Defender for Endpoint", credential


def _load_hunting(
    args: argparse.Namespace,
    credential: DeviceCodeCredential | None,
) -> tuple[list[dict[str, Any]], DeviceCodeCredential | None]:
    if args.hunting_file:
        return _load_json(args.hunting_file, "results"), credential
    tenant_id, client_id = _require_identity(args)
    credential = credential or DeviceCodeCredential(tenant_id, client_id)
    client = GraphHuntingClient(lambda: credential.get_token(GRAPH_SCOPES))
    return (
        client.run(FLEET_ENRICHMENT_QUERY, timespan=f"P{args.hunting_days}D"),
        credential,
    )


def run(args: argparse.Namespace) -> int:
    if not 1 <= args.hunting_days <= 30:
        raise ValueError("--hunting-days must be between 1 and 30")
    if not 1 <= args.page_size <= 10_000:
        raise ValueError("--page-size must be between 1 and 10000")

    policy = AuditPolicy.from_toml(args.config) if args.config else AuditPolicy()
    credential: DeviceCodeCredential | None = None
    raw_machines, source, credential = _load_machines(args, credential)
    devices = [DeviceRecord.from_machine(item) for item in raw_machines]

    if args.include_hunting or args.hunting_file:
        hunting_rows, credential = _load_hunting(args, credential)
        enrich_devices(devices, hunting_rows)
        source += " + Microsoft Graph advanced hunting"

    now = datetime.now(timezone.utc)
    findings = audit_devices(devices, policy, now=now)
    report = build_report(
        findings,
        policy,
        source=source,
        include_healthy=args.all_devices,
        generated_at=now,
    )

    prefix = _safe_prefix(args.output_prefix, now)
    written: list[Path] = []
    if args.format in {"json", "both"}:
        written.append(write_json(report, args.output_dir / f"{prefix}.json"))
    if args.format in {"csv", "both"}:
        written.append(write_csv(report, args.output_dir / f"{prefix}.csv"))

    print(format_summary(report))
    for path in written:
        print(f"Wrote {path}")

    threshold = SEVERITY_RANK[args.fail_on]
    if threshold and any(
        SEVERITY_RANK[finding.max_severity] >= threshold for finding in findings
    ):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (
        ApiError,
        AuthenticationError,
        OSError,
        PolicyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
