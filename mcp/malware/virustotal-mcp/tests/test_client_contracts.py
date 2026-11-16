# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""A packaged contract drives generated setup and server filename guards."""

import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest

from vt_mcp.client_contracts import claude_code_contract, credential_filename_denied

ROOT = Path(__file__).resolve().parents[1]


def test_packaged_contract_and_generated_guides_agree():
    canonical = files("vt_mcp").joinpath("client_contracts.json").read_bytes()
    contract = claude_code_contract()
    # Keep legacy fields compatible with older hosted-setup consumers.
    assert contract["node_minimum_major"] == 22
    assert contract["verified_node_majors"] == [22, 24]
    contract["install_commands"].clear()
    assert len(claude_code_contract()["install_commands"]) == 2
    assert json.loads(canonical)["schema_version"] == 1
    subprocess.run([sys.executable, "scripts/client_docs.py", "--check"], cwd=ROOT, check=True)


@pytest.mark.parametrize(
    "name",
    [
        ".git-credentials",
        ".PGPASS",
        ".htpasswd",
        "sample.P12",
        "sample.pfx",
        "sample.ppk",
        "sample.jks",
        "sample.keystore",
        ".env\nbackup",
        "ID_ED25519_sk",
        "C:\\Users\\you\\credentials.json",
        "C:credentials.json",
        "c:.env",
        "D:id_rsa",
        "D:kubeconfig",
        "/home/you/.npmrc",
    ],
)
def test_shared_credential_filename_rule_rejects_new_patterns_and_path_styles(name):
    assert credential_filename_denied(name)


@pytest.mark.parametrize(
    "name",
    [
        "unfamiliar.bin",
        "notes.txt",
        ".pgpass.txt",
        "public-cert.crt",
        "C:notes.txt",
        "D:sample.bin",
    ],
)
def test_filename_guard_does_not_claim_to_scan_contents(name):
    assert not credential_filename_denied(name)
