#!/usr/bin/env python3
"""Statically brute-force the finite environment-key space of stage 2.

No JavaScript is executed.  This is a Python transcription of the sample's
RC4-like transform, key derivation, and 16-byte integrity check.
"""

from __future__ import annotations

import itertools
import json
import re
import sys
from pathlib import Path

from static_deobfuscate import eval_int, matching, split_top


def rc4_drop(key: list[int], data: list[int], drop: int = 2835) -> list[int]:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    for _ in range(drop):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return out


def derive(value: str | list[int]) -> list[int]:
    data = [ord(c) for c in value] if isinstance(value, str) else list(value)
    while len(data) < 64:
        data.append(len(data) ^ 52)
    seed = [116, 103, 65, 5, 23, 171, 176, 81, 207, 244, 171, 214, 17, 111, 240, 151]
    state = rc4_drop(seed, data, 832)
    folded = state[:16]
    for offset in range(16, len(state), 16):
        for index in range(min(16, len(state) - offset)):
            folded[index] ^= state[offset + index]
    state = rc4_drop(folded, state, 461)
    seed2 = [state[i] ^ (i * 57 + 244) for i in range(16)]
    return rc4_drop(seed2, state, 200)[:32]


def short(value: str) -> list[int]:
    return derive(value)[:8]


def decrypt(blob: list[int], key: list[int]) -> bytes | None:
    if len(blob) < 16:
        return None
    tag, ciphertext = blob[:16], blob[16:]
    plain = rc4_drop(key, ciphertext, 2835)
    check = derive(plain)[:16]
    if any(a ^ b for a, b in zip(tag, check)):
        return None
    return bytes(plain)


def extract_array(source: str, name: str) -> list[int]:
    match = re.search(rf"var\s+{re.escape(name)}\s*=\s*\[", source)
    if not match:
        raise ValueError(f"array not found: {name}")
    start = match.end() - 1
    end = matching(source, start, "[", "]")
    return [eval_int(item, {}) for item in split_top(source[start + 1:end])]


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} DEOBFUSCATED_JS OUTPUT_JSON", file=sys.stderr)
        return 2
    source = Path(sys.argv[1]).read_text(encoding="utf-8")
    blobs = {
        name: extract_array(source, name)
        for name in ("verifySocketPublisher", "parseProtocolLog", "gatherOrganizationEntry")
    }

    choices = [
        ("polProxyjIgw", "bufPolicyUCUz"),
        ("dnsRule1p8U", "afpInfowIvl"),
        ("ipsecTokenjPGh", "accRulehtev"),
        ("amfiSegxMxK", "avfMaskXRs5", "ptrSetting09Rq"),
        ("nvrAction8xGJ", "kcDumpM6Am"),
        (
            ("amfiProbeAUaP", "macUUIDAM6P"),
            ("amfiProbeAUaP", "mdsActionR1G9"),
            ("asmActionh0E2", "macUUIDAM6P"),
            ("asmActionh0E2", "mdsActionR1G9"),
        ),
        ("cgdChunkBgLS", "amfiSegr624"),
        ("sbxTierA1vE", "fwPassyMkB"),
    ]

    hits = []
    for outcome in itertools.product(*choices):
        material: list[int] = []
        labels = []
        for item in outcome:
            values = item if isinstance(item, tuple) else (item,)
            labels.extend(values)
            for value in values:
                material.extend(short(value))
        key = derive(material)
        decoded = {name: decrypt(blob, key) for name, blob in blobs.items()}
        if all(value is not None for value in decoded.values()):
            hits.append({
                "outcomes": labels,
                "derived_key_hex": bytes(key).hex(),
                "payloads": {
                    name: value.decode("utf-8", errors="replace")
                    for name, value in decoded.items()
                },
            })

    Path(sys.argv[2]).write_text(json.dumps(hits, indent=2) + "\n", encoding="utf-8")
    print(f"tested 768 outcome combinations; found {len(hits)} fully validated key(s)")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
