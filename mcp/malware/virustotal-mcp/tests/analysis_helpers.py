# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Innocent, synthetic wave-five protocol fixtures."""

import hashlib

BODY = b"This is an innocent local protocol fixture.\n"
SHA = hashlib.sha256(BODY).hexdigest()
TOKEN = "synthetic-analysis-client-token"
ANALYSIS_ID = "analysis/example?literal%#é"


def analysis_response(identifier=ANALYSIS_ID, sha256=SHA, *, completed=False):
    return {
        "status": "completed" if completed else "pending",
        "analysis_id": identifier,
        "analysis_status": "completed" if completed else "in-progress",
        "sha256": sha256,
        "source": "VirusTotal via VTAI",
        "retrieved_at": "2026-09-06T12:00:00+00:00",
        "analysis_date": "2026-09-05T12:00:00+00:00",
        "stats": {"harmless": 1},
        "results": {
            "Fixture engine": {
                "engine_name": "Fixture engine",
                "engine_version": None,
                "engine_update": None,
                "category": "harmless",
                "result": "Fixture clean label",
                "method": "test",
            }
        },
        "detections": ["Fixture clean label"],
        "coverage": {"engines": 1, "categories": ["harmless"]},
        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
        "next_poll_after_seconds": None if completed else 5,
        "pending_reason": None if completed else "processing",
    }


def submission_response(sha256=SHA, size=None, *, status="submitted"):
    size = len(BODY) if size is None else size
    return {
        "status": status,
        "mode": "standard",
        "submission_id": sha256,
        "sha256": sha256,
        "size": size,
        "analysis_id": ANALYSIS_ID if status == "submitted" else None,
        "analysis_status": None,
        "next_poll_after_seconds": 5 if status == "submitted" else None,
        "can_resubmit": False,
        "report": {
            "data": {
                "id": sha256,
                "last_analysis_stats": {"harmless": 1},
                "detections": [],
                "type_description": None,
                "ai_insights": None,
            }
        }
        if status == "exists"
        else None,
    }
