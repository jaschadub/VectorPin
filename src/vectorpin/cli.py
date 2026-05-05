# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VectorPin CLI.

Subcommands:
  keygen          Generate an ed25519 signing key pair.
  pin             Sign a single (text, vector) pair (debug/demo).
  verify-pin      Verify a single Pin against ground-truth source/vector.
  audit-qdrant    Walk a Qdrant collection and report on every record's pin.

Run `vectorpin --help` for the canonical usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from vectorpin import Pin, Signer, Verifier


def _cmd_keygen(args: argparse.Namespace) -> int:
    signer = Signer.generate(key_id=args.key_id)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.key_id}.priv").write_bytes(signer.private_key_bytes())
    (out / f"{args.key_id}.pub").write_bytes(signer.public_key_bytes())
    print(f"wrote {out}/{args.key_id}.priv  (KEEP SECRET)", file=sys.stderr)
    print(f"wrote {out}/{args.key_id}.pub")
    return 0


def _load_vector(path: str) -> np.ndarray:
    p = Path(path)
    if p.suffix == ".npy":
        return np.load(p)
    if p.suffix == ".json":
        return np.asarray(json.loads(p.read_text()), dtype=np.float32)
    raise ValueError(f"unsupported vector file extension: {p.suffix}")


def _cmd_pin(args: argparse.Namespace) -> int:
    private_bytes = Path(args.private_key).read_bytes()
    signer = Signer.from_private_bytes(private_bytes, key_id=args.key_id)
    source = Path(args.source).read_text(encoding="utf-8")
    vector = _load_vector(args.vector)
    pin = signer.pin(source=source, model=args.model, vector=vector)
    print(pin.to_json())
    return 0


def _cmd_verify_pin(args: argparse.Namespace) -> int:
    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    pin = Pin.from_json(Path(args.pin).read_text())
    source = Path(args.source).read_text(encoding="utf-8") if args.source else None
    vector = _load_vector(args.vector) if args.vector else None
    result = verifier.verify(pin, source=source, vector=vector)
    if result.ok:
        print("OK")
        return 0
    print(f"FAIL [{result.error.value}] {result.detail}", file=sys.stderr)
    return 2


def _cmd_audit_qdrant(args: argparse.Namespace) -> int:
    from vectorpin.adapters.qdrant import QdrantAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    adapter = QdrantAdapter.connect(args.url, args.collection, api_key=args.api_key)

    total = pinned = ok = bad = unpinned = 0
    for rec in adapter.iter_records(batch_size=args.batch_size):
        total += 1
        if rec.pin is None:
            unpinned += 1
            continue
        pinned += 1
        result = verifier.verify(rec.pin, vector=rec.vector)
        if result.ok:
            ok += 1
        else:
            bad += 1
            print(f"FAIL {rec.id} [{result.error.value}] {result.detail}", file=sys.stderr)

    print(
        json.dumps(
            {
                "collection": args.collection,
                "total": total,
                "pinned": pinned,
                "verified_ok": ok,
                "verification_failed": bad,
                "unpinned": unpinned,
            },
            indent=2,
        )
    )
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vectorpin",
        description="Verifiable integrity for AI embedding stores.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an ed25519 signing key pair")
    p_keygen.add_argument("--key-id", required=True, help="identifier for the new key")
    p_keygen.add_argument("--output", default="keys", help="output directory (default: ./keys)")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_pin = sub.add_parser("pin", help="sign a single (text, vector) pair")
    p_pin.add_argument("--private-key", required=True, help="path to .priv key file")
    p_pin.add_argument("--key-id", required=True)
    p_pin.add_argument("--model", required=True, help="embedding model identifier")
    p_pin.add_argument("--source", required=True, help="path to source text file")
    p_pin.add_argument("--vector", required=True, help="path to vector (.npy or .json)")
    p_pin.set_defaults(func=_cmd_pin)

    p_verify = sub.add_parser("verify-pin", help="verify a Pin against ground-truth")
    p_verify.add_argument("--public-key", required=True, help="path to .pub key file")
    p_verify.add_argument("--key-id", required=True)
    p_verify.add_argument("--pin", required=True, help="path to pin JSON file")
    p_verify.add_argument("--source", help="optional path to source text for full verification")
    p_verify.add_argument("--vector", help="optional path to vector for full verification")
    p_verify.set_defaults(func=_cmd_verify_pin)

    p_audit = sub.add_parser("audit-qdrant", help="audit every pin in a Qdrant collection")
    p_audit.add_argument("--url", required=True, help="qdrant URL, e.g. http://localhost:6333")
    p_audit.add_argument("--collection", required=True)
    p_audit.add_argument("--public-key", required=True)
    p_audit.add_argument("--key-id", required=True)
    p_audit.add_argument("--api-key", default=None)
    p_audit.add_argument("--batch-size", type=int, default=256)
    p_audit.set_defaults(func=_cmd_audit_qdrant)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
