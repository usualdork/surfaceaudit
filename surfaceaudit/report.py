"""Report generation for SurfaceAudit."""

from __future__ import annotations

import base64
import copy
import csv
import io
import json
import os
import re
from collections import Counter

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from jinja2 import Environment, FileSystemLoader

from surfaceaudit.config import ScanConfig
from surfaceaudit.models import (
    AssessedAsset,
    ReportSummary,
    ScanMetadata,
    ScanReport,
    to_serializable_dict,
)

# RFC 1918 private IP ranges
_RFC1918_PATTERN = re.compile(
    r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    r"|(192\.168\.\d{1,3}\.\d{1,3})$"
)


class ReportGenerator:
    """Generates scan reports from assessed assets and metadata."""

    def generate(
        self,
        assets: list[AssessedAsset],
        metadata: ScanMetadata,
        config: ScanConfig,
    ) -> ScanReport:
        """Produce a ``ScanReport`` from assessed assets and scan metadata.

        If ``config.redact_sensitive`` is ``True``, internal IPs and
        associated hostnames are replaced with ``[REDACTED]``.
        """
        summary = self._compute_summary(assets)
        report = ScanReport(metadata=metadata, summary=summary, assets=list(assets))

        if config.redact_sensitive:
            report = self._redact(report)

        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_summary(self, assets: list[AssessedAsset]) -> ReportSummary:
        """Compute summary statistics for a list of assessed assets."""
        total_assets = len(assets)
        assets_by_type: dict[str, int] = dict(
            Counter(asset.asset_type.value for asset in assets)
        )
        assets_by_risk: dict[str, int] = dict(
            Counter(asset.risk_level.value for asset in assets)
        )
        return ReportSummary(
            total_assets=total_assets,
            assets_by_type=assets_by_type,
            assets_by_risk=assets_by_risk,
        )

    def _redact(self, report: ScanReport) -> ScanReport:
        """Return a new ``ScanReport`` with internal IPs and hostnames redacted.

        RFC 1918 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are
        replaced with ``[REDACTED]``.  Hostnames on assets whose IP is
        internal are also replaced.
        """
        redacted_assets: list[AssessedAsset] = []
        for asset in report.assets:
            asset_copy = copy.deepcopy(asset)
            if _RFC1918_PATTERN.match(asset_copy.ip):
                asset_copy.hostname = "[REDACTED]"
                asset_copy.ip = "[REDACTED]"
            redacted_assets.append(asset_copy)

        return ScanReport(
            metadata=copy.deepcopy(report.metadata),
            summary=copy.deepcopy(report.summary),
            assets=redacted_assets,
        )


class ReportFormatter:
    """Formats a ``ScanReport`` into JSON, CSV, or HTML."""

    _TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

    # -- JSON ---------------------------------------------------------------

    def to_json(self, report: ScanReport) -> str:
        """Serialize *report* to a pretty-printed JSON string."""
        return json.dumps(to_serializable_dict(report), indent=2)

    # -- CSV ----------------------------------------------------------------

    _CSV_COLUMNS = [
        "ip",
        "hostname",
        "asset_type",
        "os",
        "risk_level",
        "ports",
        "services_count",
        "vulnerabilities_count",
    ]

    def to_csv(self, report: ScanReport) -> str:
        """Flatten each asset into a row and return a CSV string."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self._CSV_COLUMNS)
        writer.writeheader()
        for asset in report.assets:
            writer.writerow(
                {
                    "ip": asset.ip,
                    "hostname": asset.hostname or "",
                    "asset_type": asset.asset_type.value,
                    "os": asset.os or "",
                    "risk_level": asset.risk_level.value,
                    "ports": ",".join(str(p) for p in asset.ports),
                    "services_count": len(asset.services),
                    "vulnerabilities_count": len(asset.vulnerabilities),
                }
            )
        return buf.getvalue()

    # -- HTML ---------------------------------------------------------------

    def to_html(self, report: ScanReport) -> str:
        """Render *report* as an HTML page using a Jinja2 template."""
        env = Environment(
            loader=FileSystemLoader(self._TEMPLATES_DIR),
            autoescape=True,
        )
        template = env.get_template("report.html")
        data = to_serializable_dict(report)
        return template.render(report=data)

    # -- SARIF --------------------------------------------------------------

    def to_sarif(self, report: ScanReport) -> str:
        """Serialize *report* to a SARIF v2.1.0 JSON string."""
        from surfaceaudit.output.sarif import SARIFFormatter
        import surfaceaudit

        return SARIFFormatter().format(report, surfaceaudit.__version__)


class ReportEncryptor:
    """Encrypts and decrypts report content using Fernet symmetric encryption."""

    _SALT_LENGTH = 16
    _KDF_ITERATIONS = 100_000

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a Fernet key from a password and salt using PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, content: bytes, password: str) -> bytes:
        """Encrypt *content* with *password* using Fernet.

        Returns ``salt + encrypted_data`` where salt is 16 bytes.
        """
        salt = os.urandom(self._SALT_LENGTH)
        key = self._derive_key(password, salt)
        encrypted_data = Fernet(key).encrypt(content)
        return salt + encrypted_data

    def decrypt(self, content: bytes, password: str) -> bytes:
        """Decrypt *content* that was encrypted with :meth:`encrypt`."""
        salt = content[: self._SALT_LENGTH]
        encrypted_data = content[self._SALT_LENGTH :]
        key = self._derive_key(password, salt)
        return Fernet(key).decrypt(encrypted_data)
