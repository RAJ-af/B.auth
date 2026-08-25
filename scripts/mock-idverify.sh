#!/usr/bin/env bash
# Mock government-ID verifier implementing contract_version 1.
# Reads one JSON object on stdin, writes one JSON object on stdout, ALWAYS exits 0
# when the input is well-formed (verification failure is a RESULT, not an error).
set -euo pipefail
MODE="${MOCK_IDVERIFY_MODE:-verified_single}"
IN="$(cat)"
python3 - "$MODE" "$IN" <<'PY'
import json, os, sys
mode = sys.argv[1]
try:
    raw = sys.argv[2] if len(sys.argv) > 2 else ""
    inp = json.loads(raw or "{}")
except json.JSONDecodeError:
    print("mock-idverify: stdin was not JSON", file=sys.stderr); sys.exit(64)
if inp.get("contract_version") != 1:
    print("mock-idverify: unsupported contract_version", file=sys.stderr); sys.exit(65)
out = {"contract_version": 1}
if mode == "verified_single":
    out |= {"verified": True,
            "identities": [{"type": inp.get("document_type", "generic"),
                            "number_masked": "••••1234",
                            "name": inp.get("full_name", ""),
                            "is_minor": False}],
            "warnings": []}
elif mode == "multi_minor":
    out |= {"verified": True,
            "identities": [
                {"type": "guardian", "number_masked": "••••0000",
                 "name": "Guardian", "is_minor": False},
                {"type": "dependent", "number_masked": "••••0001",
                 "name": "Child One", "is_minor": True},
                {"type": "dependent", "number_masked": "••••0002",
                 "name": "Child Two", "is_minor": True}],
            "warnings": ["multiple identities on document"]}
elif mode == "not_verified":
    out |= {"verified": False, "identities": [], "warnings": ["liveness failed"]}
elif mode == "infra_fail":
    print("upstream registry unreachable", file=sys.stderr)
    out |= {"verified": False, "identities": [],
            "warnings": ["upstream_infrastructure_error"]}
else:                                            # slow
    import time; time.sleep(120)
print(json.dumps(out))
PY
