#!/home/h3x/.venvs/eyestat/bin/python3
"""txt_to_json.py — wrap a raw symbol sequence into the data format eyestat_gpu_runner reads.

Reads a file containing one digit per symbol (e.g. "43212123..." for an N=5 alphabet)
and writes the noita_eye_data.json-compatible structure.

USAGE
=====
  # Single message, N inferred from data:
  python3 txt_to_json.py test.txt test.json

  # Force a specific alphabet size (e.g. if your data doesn't use all symbols):
  python3 txt_to_json.py test.txt test.json --n 5

  # Split into multiple messages at given positions (mirrors the 9-message
  # structure of the real Noita data):
  python3 txt_to_json.py test.txt test.json --split 50,120,200
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="Input text file (one symbol per character)")
    p.add_argument("output", help="Output JSON file")
    p.add_argument("--n", type=int, default=None,
                   help="Alphabet size (default: max symbol value + 1)")
    p.add_argument("--split", default="",
                   help="Comma-separated split positions to break into multiple messages")
    args = p.parse_args()

    text = Path(args.input).read_text().strip().replace("\n", "").replace(" ", "")
    try:
        symbols = [int(c) for c in text]
    except ValueError as e:
        print(f"ERROR: input must contain only digits 0-9; got: {e}", file=sys.stderr)
        sys.exit(1)

    if not symbols:
        print("ERROR: input is empty", file=sys.stderr)
        sys.exit(1)

    N = args.n if args.n is not None else max(symbols) + 1
    if any(s >= N or s < 0 for s in symbols):
        bad = next(s for s in symbols if s >= N or s < 0)
        print(f"ERROR: symbol {bad} out of range for N={N}", file=sys.stderr)
        sys.exit(1)

    if args.split:
        split_positions = sorted(int(x) for x in args.split.split(","))
        ciphertexts = []
        last = 0
        for pos in split_positions:
            ciphertexts.append(symbols[last:pos])
            last = pos
        ciphertexts.append(symbols[last:])
        ciphertexts = [c for c in ciphertexts if c]  # drop empty
    else:
        ciphertexts = [symbols]

    data = {"ciphertexts": ciphertexts, "deck_size": N}
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)

    total = sum(len(c) for c in ciphertexts)
    print(f"Wrote {args.output}")
    print(f"  {len(ciphertexts)} message(s), {total} total symbols, N={N}")
    from collections import Counter
    counts = Counter(symbols)
    print(f"  symbol distribution: " +
          ", ".join(f"{s}={c}" for s, c in sorted(counts.items())))


if __name__ == "__main__":
    main()
