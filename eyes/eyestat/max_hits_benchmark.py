#!/home/h3x/.venvs/eyestat/bin/python3
"""max_hits_benchmark.py — what's the ceiling on `hits` for each language?

Tests several scenarios to bracket the answer:

1. Hard upper bound from the algorithm itself (regardless of input):
   number of distinct substrings of length [4,20] possible in 1036 chars.

2. Dictionary-size cap.

3. Pack maximum: greedily concatenate dict words into a 1036-char string
   to find the max we can actually achieve in this length.

4. Natural-text ceiling: score real Finnish/English text of equivalent length.

5. Random-text noise floor: score uniformly random letter strings.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import eyestat_scoring as S


TEXT_LEN = 1036  # total CT positions across all 9 Noita messages
MIN_WORD_LEN = 4  # runner default
MAX_WORD_LEN = 20


def load_dict(lang: str, path: str) -> S.Dictionary:
    d = S.Dictionary(lang)
    d.load(Path(path))
    return d


def hard_upper_bound_substrings(n: int, mn: int, mx: int) -> int:
    """Count of (position, length) candidate substrings in n chars."""
    total = 0
    for L in range(mn, mx + 1):
        if n >= L:
            total += n - L + 1
    return total


def pack_max_words(dictionary: S.Dictionary, target_len: int) -> str:
    """Greedy: pack as many distinct dict words as possible into target_len
    chars by simple concatenation. This is a LOWER bound on the packing max
    — actual max can use substring overlap (e.g. 'kalalla' has 'kala' inside)."""
    words_by_len = sorted(dictionary.words, key=lambda w: (len(w), w))
    out = []
    used = 0
    for w in words_by_len:
        if used + len(w) > target_len:
            continue
        out.append(w)
        used += len(w)
        if used == target_len:
            break
    return "".join(out)


def random_letter_text(n: int, alphabet: str, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def main():
    print("=" * 72)
    print(f"Max-hits ceiling analysis  (text length = {TEXT_LEN} chars)")
    print(f"min_word_len = {MIN_WORD_LEN}, max_word_len = {MAX_WORD_LEN}")
    print("=" * 72)

    # 1. Hard algorithm bound
    ub = hard_upper_bound_substrings(TEXT_LEN, MIN_WORD_LEN, MAX_WORD_LEN)
    print(f"\n[1] Algorithmic upper bound (impossible in practice):")
    print(f"    distinct candidate substrings in {TEXT_LEN} chars, length 4-20")
    print(f"    = {ub:,} substrings")
    print(f"    This is the absolute ceiling — every substring would have to")
    print(f"    coincidentally be a unique dictionary word (impossible).")

    # 2-5. Per dictionary
    dicts = [
        ("fi",  "extra_words_fi.txt",  "abcdefghijklmnopqrstuvwxyzäöå"),
        ("krl", "extra_words_krl.txt", "abcdefghijklmnopqrstuvwxyzäöč"),
        ("en",  "noita_wordlist.txt",  "abcdefghijklmnopqrstuvwxyz"),
    ]

    for lang, path, alphabet in dicts:
        d = load_dict(lang, path)
        print(f"\n--- {lang} dictionary ({len(d):,} words) ---")

        # 2. Dict-size cap (cumulative across all length bins)
        cnt_by_len = {}
        for w in d.words:
            if MIN_WORD_LEN <= len(w) <= MAX_WORD_LEN:
                cnt_by_len[len(w)] = cnt_by_len.get(len(w), 0) + 1
        words_in_range = sum(cnt_by_len.values())
        print(f"[2] Dictionary-size cap:")
        print(f"    {words_in_range:,} words in length range [{MIN_WORD_LEN}, {MAX_WORD_LEN}]")
        print(f"        (out of {len(d):,} total)")

        # 3. Greedy concat packing — lower bound on packing max
        packed = pack_max_words(d, TEXT_LEN)
        hits, _ = S.count_dictionary_hits(packed, d, MIN_WORD_LEN, MAX_WORD_LEN)
        print(f"[3] Greedy-pack lower bound on packing max:")
        print(f"    distinct hits when concatenating shortest dict words")
        print(f"    into {TEXT_LEN} chars = {hits} hits")

        # 3b. Better packing: use shorter dict words preferentially (more per length)
        # Also count overlap-included hits from the same packed string
        # — substring matches can find embedded words in the concat too

        # 4. Natural-text ceilings via stress-test: generate a string by
        # interleaving short common dict words separated by single random chars
        # (simulates "rich" text with high word density)
        rng = random.Random(42)
        short_words = sorted([w for w in d.words if MIN_WORD_LEN <= len(w) <= 6],
                              key=lambda w: (len(w), w))
        if short_words:
            parts, used = [], 0
            for w in short_words:
                if used + len(w) + 1 > TEXT_LEN:
                    break
                parts.append(w)
                used += len(w) + 1
            rich = " ".join(parts)[:TEXT_LEN]
            rich = rich.replace(" ", rng.choice(alphabet))  # remove spaces
            hits, _ = S.count_dictionary_hits(rich, d, MIN_WORD_LEN, MAX_WORD_LEN)
            print(f"[4] Word-rich text (short words concatenated):")
            print(f"    {hits} hits in a deliberately word-dense {TEXT_LEN}-char string")

        # 5. Noise floor: uniformly random letters
        random_hits = []
        for trial in range(5):
            txt = random_letter_text(TEXT_LEN, alphabet, seed=trial)
            h, _ = S.count_dictionary_hits(txt, d, MIN_WORD_LEN, MAX_WORD_LEN)
            random_hits.append(h)
        avg = sum(random_hits) / len(random_hits)
        print(f"[5] Random-text noise floor (5 trials, uniform letters):")
        print(f"    hits = {random_hits}, avg = {avg:.1f}")

    # 6. Per-algorithm consideration
    print("\n" + "=" * 72)
    print("Per-algorithm reachable max")
    print("=" * 72)
    print("""
The hit-counting function operates on the DECRYPTED LETTER STRING regardless
of which cipher produced it — so the ceiling is the same for every algorithm
on paper. The practical reachable max differs by family:

  GAK / xGAK / KAK / CFB / OFB / Vigenère
    Decrypted output is in the 83-rune alphabet, then mapped to letters via
    Hungarian assignment (1 letter per rune, surjective: ~3 runes share each
    letter). The 83→26-or-29 collapse means some signal is lost, but the
    SCORED STRING is still 1036 letters — same ceiling as any other source.

  Card ciphers (Pontifex / Mirdek / Card Chameleon)
    Work natively in 26-letter alphabet; runes are pre-mapped by frequency
    rank before decryption. Output is also a 1036-letter string.

  Bottom line: the ceiling on `hits` is governed by the TEXT (length, language,
  word density), not by the cipher. A correct decryption of the real Noita
  messages would land somewhere between the noise floor and the natural-text
  ceiling for the actual language used.
""")


if __name__ == "__main__":
    main()
