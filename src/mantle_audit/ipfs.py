"""Pinata IPFS integration for uploading audit reports."""

from __future__ import annotations

import json

import requests

from .config import Config

PINATA_PIN_FILE_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_PIN_JSON_URL = "https://api.pinata.cloud/pinning/pinJSONToIPFS"


def _check_pinata_config() -> list[str]:
    missing = []
    if not Config.PINATA_API_KEY:
        missing.append("PINATA_API_KEY")
    if not Config.PINATA_SECRET_KEY:
        missing.append("PINATA_SECRET_KEY")
    return missing


def upload_json(data: dict, filename: str = "audit-report.json") -> str:
    """Upload JSON data to Pinata IPFS.

    Args:
        data: Dictionary to upload.
        filename: Name for the pinned content.

    Returns:
        IPFS CID (IpfsHash).

    Raises:
        RuntimeError: If Pinata config is missing or upload fails.
    """
    missing = _check_pinata_config()
    if missing:
        raise RuntimeError(f"Missing Pinata config: {', '.join(missing)}")

    headers = {
        "Content-Type": "application/json",
        "pinata_api_key": Config.PINATA_API_KEY,
        "pinata_secret_api_key": Config.PINATA_SECRET_KEY,
    }
    payload = {
        "pinataContent": data,
        "pinataMetadata": {"name": filename},
    }

    resp = requests.post(PINATA_PIN_JSON_URL, json=payload, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Pinata upload failed ({resp.status_code}): {resp.text}")

    return resp.json()["IpfsHash"]


def upload_file(content: bytes, filename: str) -> str:
    """Upload raw bytes to Pinata IPFS.

    Args:
        content: File content as bytes.
        filename: Filename for the upload.

    Returns:
        IPFS CID (IpfsHash).

    Raises:
        RuntimeError: If Pinata config is missing or upload fails.
    """
    missing = _check_pinata_config()
    if missing:
        raise RuntimeError(f"Missing Pinata config: {', '.join(missing)}")

    headers = {
        "pinata_api_key": Config.PINATA_API_KEY,
        "pinata_secret_api_key": Config.PINATA_SECRET_KEY,
    }
    files = {"file": (filename, content)}

    resp = requests.post(PINATA_PIN_FILE_URL, files=files, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Pinata upload failed ({resp.status_code}): {resp.text}")

    return resp.json()["IpfsHash"]


def upload_report(report_json: str) -> str:
    """Upload an audit report JSON string to IPFS.

    Args:
        report_json: JSON string of the audit report.

    Returns:
        IPFS CID.
    """
    data = json.loads(report_json)
    return upload_json(data, filename="audit-report.json")


def get_ipfs_url(cid: str) -> str:
    """Return a public IPFS gateway URL for a CID."""
    return f"https://gateway.pinata.cloud/ipfs/{cid}"
