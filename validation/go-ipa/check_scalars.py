#!/usr/bin/env python3
"""Compare the runtime challenge and IPA final-scalar LE encodings explicitly."""
import hashlib
import json
import sys

MODULUS = 13108968793781547619861935127046491459309155893440570251786403306729687672801

def load(path):
    with open(path) as source:
        return {(r["n"], r["mode"]): r for r in map(json.loads, source)}

go, rust = map(load, sys.argv[1:3])
assert len(go) == len(rust) == 12 and go.keys() == rust.keys()
samples = []
digest = hashlib.sha256()
for key in sorted(go):
    for kind in ["challenge", "ipa_final_scalar"]:
        a = bytes.fromhex(go[key]["challenge"] if kind == "challenge" else go[key]["proof"][-64:])
        b = bytes.fromhex(rust[key]["challenge"] if kind == "challenge" else rust[key]["proof"][-64:])
        assert len(a) == 32 and a == b
        value = int.from_bytes(a, "little")
        assert value < MODULUS and value.to_bytes(32, "little") == a
        digest.update(a)
        samples.append({"n": key[0], "mode": key[1], "kind": kind, "canonical_le_hex": a.hex(), "integer": str(value)})
json.dump({"matched_canonical_scalar_encodings": len(samples), "sha256": digest.hexdigest(), "samples": samples}, sys.stdout, indent=2)
print()
