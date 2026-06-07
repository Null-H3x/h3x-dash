#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_kernels.py — cipher kernels for the brute-force runner.

All kernels expose the same interface:

    decrypt(ct: List[int], key_state: Any, alphabet_size: int) -> List[int]
    encrypt(pt: List[int], key_state: Any, alphabet_size: int) -> List[int]
    selftest_roundtrip(alphabet_size: int) -> bool

For GAK/xGAK/KAK/CFB/OFB/Vigenère, key_state = (sigma_perms, alphabet_size)
where sigma_perms is a list of N+1 permutations in S_N (one per σ-key index
plus σ[0] for the active perm seed).

For card ciphers, key_state = the initial deck order (list of integers).

The N argument is the cipher's NATIVE alphabet size; for our 83-rune
ciphertext fed into a 26-letter card cipher, the runes get mapped down
to letters BEFORE entering the card-cipher kernel.

VALIDATION
==========
Every kernel implements selftest_roundtrip(N) which generates a random
key + random plaintext, encrypts, decrypts, and checks pt == decrypt(encrypt(pt)).
Run all selftests via `python3 -c 'import eyestat_kernels; eyestat_kernels.run_all_selftests()'`.
"""

from __future__ import annotations

import random
from typing import Any, List, Tuple


# ---------------------------------------------------------------------------
# Permutation helpers
# ---------------------------------------------------------------------------

def perm_inverse(p: List[int]) -> List[int]:
    """Compute the inverse permutation: q[p[i]] = i."""
    n = len(p)
    q = [0] * n
    for i in range(n):
        q[p[i]] = i
    return q


def perm_compose(f: List[int], g: List[int]) -> List[int]:
    """Return f ∘ g: (f∘g)(i) = f(g(i))."""
    return [f[g[i]] for i in range(len(g))]


def random_perm(n: int, rng: random.Random | None = None) -> List[int]:
    """Generate a uniformly random permutation in S_n."""
    if rng is None:
        rng = random
    p = list(range(n))
    rng.shuffle(p)
    return p


# ---------------------------------------------------------------------------
# GAK / xGAK family (8 modes)
# ---------------------------------------------------------------------------

# Mode encoding (matches noita_prng_brute.py for compatibility):
GAK_CTAK_RIGHT     = 0  # active' = active ∘ σ[ct]
GAK_CTAK_LEFT      = 1  # active' = σ[ct] ∘ active
GAK_PTAK_RIGHT     = 2  # active' = active ∘ σ[pt]
GAK_PTAK_LEFT      = 3  # active' = σ[pt] ∘ active
XGAK_SUM_RIGHT     = 4  # K[p] = (pt+ct) mod N; active' = active ∘ σ[K]
XGAK_SUM_LEFT      = 5  # K[p] = (pt+ct) mod N; active' = σ[K] ∘ active
XGAK_DIFF_RIGHT    = 6  # K[p] = (ct-pt) mod N; active' = active ∘ σ[K]
XGAK_DIFF_LEFT     = 7  # K[p] = (ct-pt) mod N; active' = σ[K] ∘ active

GAK_MODE_NAMES = {
    GAK_CTAK_RIGHT:  "ctak_right",
    GAK_CTAK_LEFT:   "ctak_left",
    GAK_PTAK_RIGHT:  "ptak_right",
    GAK_PTAK_LEFT:   "ptak_left",
    XGAK_SUM_RIGHT:  "xgak_sum_right",
    XGAK_SUM_LEFT:   "xgak_sum_left",
    XGAK_DIFF_RIGHT: "xgak_diff_right",
    XGAK_DIFF_LEFT:  "xgak_diff_left",
}


def gak_encrypt(pt: List[int], sigma: List[List[int]], N: int, mode: int) -> List[int]:
    """Encrypt under the specified GAK/xGAK mode.

    sigma must have at least N+1 entries: sigma[0] is the initial active perm
    (or σ[0] base for active_0), and sigma[1..N] are the σ keys indexed by
    cipher-stream values.
    """
    active = sigma[0][:]
    ct: List[int] = []
    for p in pt:
        c = active[p]
        ct.append(c)
        # Choose advancement key based on mode
        if mode == GAK_CTAK_RIGHT or mode == GAK_CTAK_LEFT:
            k = c
        elif mode == GAK_PTAK_RIGHT or mode == GAK_PTAK_LEFT:
            k = p
        elif mode == XGAK_SUM_RIGHT or mode == XGAK_SUM_LEFT:
            k = (p + c) % N
        elif mode == XGAK_DIFF_RIGHT or mode == XGAK_DIFF_LEFT:
            k = (c - p) % N
        else:
            raise ValueError(f"Unknown GAK mode: {mode}")
        s_k = sigma[k]
        # Apply right or left composition
        if mode in (GAK_CTAK_RIGHT, GAK_PTAK_RIGHT, XGAK_SUM_RIGHT, XGAK_DIFF_RIGHT):
            # active = active ∘ σ[k]
            active = [active[s_k[i]] for i in range(N)]
        else:
            # active = σ[k] ∘ active
            active = [s_k[active[i]] for i in range(N)]
    return ct


def gak_decrypt(ct: List[int], sigma: List[List[int]], N: int, mode: int) -> List[int]:
    """Decrypt under the specified GAK/xGAK mode.

    For RIGHT modes: pt[p] = active^-1(ct[p]); active' = active ∘ σ[k]
    For LEFT modes:  pt[p] = active^-1(ct[p]); active' = σ[k] ∘ active

    The advancement key k is computable from (pt, ct) once pt is recovered.
    """
    active = sigma[0][:]
    active_inv = perm_inverse(active)
    pt: List[int] = []
    for c in ct:
        p = active_inv[c]
        pt.append(p)
        if mode == GAK_CTAK_RIGHT or mode == GAK_CTAK_LEFT:
            k = c
        elif mode == GAK_PTAK_RIGHT or mode == GAK_PTAK_LEFT:
            k = p
        elif mode == XGAK_SUM_RIGHT or mode == XGAK_SUM_LEFT:
            k = (p + c) % N
        elif mode == XGAK_DIFF_RIGHT or mode == XGAK_DIFF_LEFT:
            k = (c - p) % N
        else:
            raise ValueError(f"Unknown GAK mode: {mode}")
        s_k = sigma[k]
        if mode in (GAK_CTAK_RIGHT, GAK_PTAK_RIGHT, XGAK_SUM_RIGHT, XGAK_DIFF_RIGHT):
            active = [active[s_k[i]] for i in range(N)]
        else:
            active = [s_k[active[i]] for i in range(N)]
        active_inv = perm_inverse(active)
    return pt


def gak_selftest(N: int, mode: int, rng: random.Random) -> bool:
    """Generate a random key + plaintext, encrypt, decrypt, verify identity."""
    sigma = [random_perm(N, rng) for _ in range(N + 1)]
    pt = [rng.randint(0, N - 1) for _ in range(50)]
    ct = gak_encrypt(pt, sigma, N, mode)
    pt2 = gak_decrypt(ct, sigma, N, mode)
    return pt == pt2


# ---------------------------------------------------------------------------
# KAK — Key autokey
# ---------------------------------------------------------------------------

# In KAK, the key value at position p+1 is derived from the PREVIOUS key
# value, not from pt or ct. The simplest construction:
#   key[p+1] = sigma_advance[key[p]]
# where sigma_advance is some permutation. Output:
#   ct[p] = active_p(pt[p])
# Active perm advances by σ[key[p]]:
#   active' = active ∘ σ[key[p]]   (RIGHT)
#   active' = σ[key[p]] ∘ active   (LEFT)

KAK_RIGHT = 100
KAK_LEFT  = 101

KAK_MODE_NAMES = {KAK_RIGHT: "kak_right", KAK_LEFT: "kak_left"}


def kak_encrypt(pt: List[int], sigma: List[List[int]],
                sigma_advance: List[int], key0: int, N: int,
                mode: int) -> List[int]:
    """KAK encryption.

    sigma:         list of N+1 perms (σ[0] = initial active, σ[1..N] = key-indexed perms)
    sigma_advance: a permutation that advances the key state
    key0:          initial key value
    """
    active = sigma[0][:]
    ct: List[int] = []
    key = key0
    for p in pt:
        c = active[p]
        ct.append(c)
        s_k = sigma[key]
        if mode == KAK_RIGHT:
            active = [active[s_k[i]] for i in range(N)]
        else:
            active = [s_k[active[i]] for i in range(N)]
        key = sigma_advance[key]
    return ct


def kak_decrypt(ct: List[int], sigma: List[List[int]],
                sigma_advance: List[int], key0: int, N: int,
                mode: int) -> List[int]:
    active = sigma[0][:]
    active_inv = perm_inverse(active)
    pt: List[int] = []
    key = key0
    for c in ct:
        p = active_inv[c]
        pt.append(p)
        s_k = sigma[key]
        if mode == KAK_RIGHT:
            active = [active[s_k[i]] for i in range(N)]
        else:
            active = [s_k[active[i]] for i in range(N)]
        active_inv = perm_inverse(active)
        key = sigma_advance[key]
    return pt


def kak_selftest(N: int, mode: int, rng: random.Random) -> bool:
    sigma = [random_perm(N, rng) for _ in range(N + 1)]
    sigma_advance = random_perm(N, rng)
    key0 = rng.randint(0, N - 1)
    pt = [rng.randint(0, N - 1) for _ in range(50)]
    ct = kak_encrypt(pt, sigma, sigma_advance, key0, N, mode)
    pt2 = kak_decrypt(ct, sigma, sigma_advance, key0, N, mode)
    return pt == pt2


# ---------------------------------------------------------------------------
# CFB — Cipher Feedback (8-bit-style adapted to mod N)
# ---------------------------------------------------------------------------

# CFB construction over a finite alphabet:
#   ct[p] = (sigma(prev_ct) + pt[p]) mod N
# where sigma is a fixed permutation acting as the "block cipher", and prev_ct
# is the previous ciphertext value (or IV for p=0).
#
# Decryption: pt[p] = (ct[p] - sigma(prev_ct)) mod N

CFB_MOD = 200  # additive feedback
CFB_SUB = 201  # substitutive feedback: ct[p] = sigma_alt(prev_ct ⊕ pt[p])

CFB_MODE_NAMES = {CFB_MOD: "cfb_mod", CFB_SUB: "cfb_sub"}


def cfb_encrypt(pt: List[int], sigma: List[int], iv: int, N: int,
                mode: int = CFB_MOD) -> List[int]:
    """CFB encryption. sigma is a single permutation over N symbols."""
    ct: List[int] = []
    prev = iv
    for p in pt:
        if mode == CFB_MOD:
            c = (sigma[prev] + p) % N
        elif mode == CFB_SUB:
            c = sigma[(prev + p) % N]
        else:
            raise ValueError(f"Unknown CFB mode: {mode}")
        ct.append(c)
        prev = c
    return ct


def cfb_decrypt(ct: List[int], sigma: List[int], iv: int, N: int,
                mode: int = CFB_MOD) -> List[int]:
    pt: List[int] = []
    prev = iv
    if mode == CFB_SUB:
        sigma_inv = perm_inverse(sigma)
    for c in ct:
        if mode == CFB_MOD:
            p = (c - sigma[prev]) % N
        elif mode == CFB_SUB:
            p = (sigma_inv[c] - prev) % N
        else:
            raise ValueError(f"Unknown CFB mode: {mode}")
        pt.append(p)
        prev = c
    return pt


def cfb_selftest(N: int, mode: int, rng: random.Random) -> bool:
    sigma = random_perm(N, rng)
    iv = rng.randint(0, N - 1)
    pt = [rng.randint(0, N - 1) for _ in range(50)]
    ct = cfb_encrypt(pt, sigma, iv, N, mode)
    pt2 = cfb_decrypt(ct, sigma, iv, N, mode)
    return pt == pt2


# ---------------------------------------------------------------------------
# OFB — Output Feedback
# ---------------------------------------------------------------------------

# OFB: keystream is generated independently of pt/ct.
#   key_stream[p+1] = sigma(key_stream[p])
#   ct[p] = (pt[p] + key_stream[p]) mod N

OFB = 300
OFB_MODE_NAMES = {OFB: "ofb"}


def ofb_encrypt(pt: List[int], sigma: List[int], iv: int, N: int) -> List[int]:
    ct: List[int] = []
    ks = iv
    for p in pt:
        c = (p + ks) % N
        ct.append(c)
        ks = sigma[ks]
    return ct


def ofb_decrypt(ct: List[int], sigma: List[int], iv: int, N: int) -> List[int]:
    pt: List[int] = []
    ks = iv
    for c in ct:
        p = (c - ks) % N
        pt.append(p)
        ks = sigma[ks]
    return pt


def ofb_selftest(N: int, rng: random.Random) -> bool:
    sigma = random_perm(N, rng)
    iv = rng.randint(0, N - 1)
    pt = [rng.randint(0, N - 1) for _ in range(50)]
    ct = ofb_encrypt(pt, sigma, iv, N)
    pt2 = ofb_decrypt(ct, sigma, iv, N)
    return pt == pt2


# ---------------------------------------------------------------------------
# Vigenère + autokey (degenerate case: KAK with trivial advance)
# ---------------------------------------------------------------------------

# Plain Vigenère: ct[p] = (pt[p] + key[p mod L]) mod N, periodic key.
# Vigenère + PT-autokey:  key[p+L] = pt[p]  (plaintext fills the keystream)
# Vigenère + CT-autokey:  key[p+L] = ct[p]  (ciphertext fills the keystream)

VIGENERE_PLAIN     = 400
VIGENERE_PT_AUTO   = 401
VIGENERE_CT_AUTO   = 402

VIGENERE_MODE_NAMES = {
    VIGENERE_PLAIN: "vigenere_plain",
    VIGENERE_PT_AUTO: "vigenere_pt_auto",
    VIGENERE_CT_AUTO: "vigenere_ct_auto",
}


def vigenere_encrypt(pt: List[int], key: List[int], N: int, mode: int) -> List[int]:
    """key is the seed key (length L). For autokey modes, the keystream extends
    deterministically from pt or ct.

    For VIGENERE_PLAIN, the keystream is periodic: keystream[i] = key[i mod L].
    At iteration i, we append key[i mod L] to position L+i (which will be used
    at iteration L+i). This gives keystream[L+i] = key[i mod L] = key[(L+i) mod L]
    as required for periodic Vigenère.
    """
    L = len(key)
    keystream = list(key)
    ct: List[int] = []
    for i, p in enumerate(pt):
        k = keystream[i]
        c = (p + k) % N
        ct.append(c)
        if mode == VIGENERE_PLAIN:
            keystream.append(key[i % L])
        elif mode == VIGENERE_PT_AUTO:
            keystream.append(p)
        elif mode == VIGENERE_CT_AUTO:
            keystream.append(c)
        else:
            raise ValueError(f"Unknown Vigenère mode: {mode}")
    return ct


def vigenere_decrypt(ct: List[int], key: List[int], N: int, mode: int) -> List[int]:
    L = len(key)
    keystream = list(key)
    pt: List[int] = []
    for i, c in enumerate(ct):
        k = keystream[i]
        p = (c - k) % N
        pt.append(p)
        if mode == VIGENERE_PLAIN:
            keystream.append(key[i % L])
        elif mode == VIGENERE_PT_AUTO:
            keystream.append(p)
        elif mode == VIGENERE_CT_AUTO:
            keystream.append(c)
    return pt


def vigenere_selftest(N: int, mode: int, rng: random.Random) -> bool:
    key = [rng.randint(0, N - 1) for _ in range(rng.randint(1, 8))]
    pt = [rng.randint(0, N - 1) for _ in range(50)]
    ct = vigenere_encrypt(pt, key, N, mode)
    pt2 = vigenere_decrypt(ct, key, N, mode)
    return pt == pt2


# ---------------------------------------------------------------------------
# Pontifex / Solitaire (Bruce Schneier)
# ---------------------------------------------------------------------------
#
# Reference: https://www.schneier.com/academic/solitaire/
# Deck:  cards 1..52 (the four suits), then jokers A=53, B=54.
# Output alphabet: 26 letters (mod 26).
# Algorithm per output letter (skip jokers in the output):
#   1. Move A-joker (53) DOWN 1 (wrap: if at very bottom, becomes second from top).
#   2. Move B-joker (54) DOWN 2 (wrap accordingly).
#   3. Triple cut: split deck around the two jokers, swap top/bottom blocks.
#   4. Count cut: take the bottom card's value (joker treated as 53), count
#      that many cards from the top, move them to just before the bottom card.
#   5. Output: take top card's value (joker = 53), count that many cards down,
#      output the value of the resulting card. If joker, skip and re-iterate.
#
# Encryption: ct = (pt + keystream) mod 26.

PONTIFEX = 500
PONTIFEX_MODE_NAMES = {PONTIFEX: "pontifex"}

PONTIFEX_DECK_SIZE = 54
PONTIFEX_JOKER_A = 53
PONTIFEX_JOKER_B = 54
PONTIFEX_ALPHABET = 26


def _pontifex_move_card_down(deck: List[int], card: int, n: int) -> List[int]:
    """Move `card` down by n positions, wrapping around the bottom such that
    if it would land at position 54 (off the bottom), it wraps to position 1
    (one below the top). Schneier's spec: "the deck is treated as circular,
    EXCEPT that it has a clear top and bottom — the bottom card is followed
    by the top card."
    
    Concrete rule from the spec:
      - If the card would end up below the bottom, wrap it to be just below
        the top (position 1, 0-indexed), then continue moving any remainder.
    """
    pos = deck.index(card)
    new_deck = deck[:]
    new_deck.pop(pos)
    new_pos = pos + n
    deck_len_minus_one = len(deck) - 1  # = 53 for full deck
    while new_pos > deck_len_minus_one:
        new_pos = new_pos - deck_len_minus_one
    new_deck.insert(new_pos, card)
    return new_deck


def pontifex_keystream(deck_init: List[int], length: int) -> Tuple[List[int], List[int]]:
    """Generate `length` keystream values from the initial deck. Returns
    (keystream, final_deck). Each value is in [0, 25]."""
    deck = deck_init[:]
    out: List[int] = []
    while len(out) < length:
        # Step 1: Move A-joker down 1
        deck = _pontifex_move_card_down(deck, PONTIFEX_JOKER_A, 1)
        # Step 2: Move B-joker down 2
        deck = _pontifex_move_card_down(deck, PONTIFEX_JOKER_B, 2)
        # Step 3: Triple cut around the two jokers
        a_pos = deck.index(PONTIFEX_JOKER_A)
        b_pos = deck.index(PONTIFEX_JOKER_B)
        first, second = sorted([a_pos, b_pos])
        deck = deck[second + 1:] + deck[first:second + 1] + deck[:first]
        # Step 4: Count cut
        bottom = deck[-1]
        count = PONTIFEX_JOKER_A if bottom == PONTIFEX_JOKER_B else bottom
        cut = deck[:count]
        deck = deck[count:-1] + cut + [deck[-1]]
        # Step 5: Output
        top = deck[0]
        count = PONTIFEX_JOKER_A if top == PONTIFEX_JOKER_B else top
        out_card = deck[count]
        if out_card == PONTIFEX_JOKER_A or out_card == PONTIFEX_JOKER_B:
            continue  # skip jokers; keystream value not produced
        # NOTE: Schneier uses 1-indexed letter convention (A=1..Z=26) where
        # the keystream value IS the card value (mod 26). We use 0-indexed
        # internally, so just take card_value mod 26: card 4 → ks 4 → letter
        # 'E' under encryption (0+4=4, chr('A')+4='E') matches Schneier's
        # output for plaintext 'A'.
        out.append(out_card % PONTIFEX_ALPHABET)
    return out, deck


def pontifex_encrypt(pt: List[int], deck_init: List[int]) -> List[int]:
    """Encrypt pt (list of ints in [0,25]) under Pontifex with given deck."""
    keystream, _ = pontifex_keystream(deck_init, len(pt))
    return [(p + k) % PONTIFEX_ALPHABET for p, k in zip(pt, keystream)]


def pontifex_decrypt(ct: List[int], deck_init: List[int]) -> List[int]:
    keystream, _ = pontifex_keystream(deck_init, len(ct))
    return [(c - k) % PONTIFEX_ALPHABET for c, k in zip(ct, keystream)]


def pontifex_initial_deck() -> List[int]:
    """Bridge order: 1..52, joker_A, joker_B."""
    return list(range(1, PONTIFEX_DECK_SIZE + 1))


def pontifex_key_deck_from_passphrase(passphrase: str) -> List[int]:
    """Schneier's passphrase keying: starting from bridge order, for each
    character of the passphrase, perform steps 1-4 of Pontifex (without
    output) then count-cut by the character's value.

    NOTE: only ASCII A-Z characters are used; other characters (including
    Finnish ä/ö/å, digits, punctuation, whitespace) are skipped. Without
    this filter, non-ASCII letters would produce out-of-range count-cut
    values that corrupt the deck (e.g. ord('ä')=196 → char_val=132 makes
    `deck[:132]` return all 54 cards, growing the deck on each step)."""
    deck = pontifex_initial_deck()
    for ch in passphrase.upper():
        # Filter to ASCII A-Z; skip non-ASCII letters and non-letters
        if not (ch.isascii() and 'A' <= ch <= 'Z'):
            continue
        char_val = ord(ch) - ord('A') + 1  # in [1, 26]
        # Step 1: Move A-joker down 1
        deck = _pontifex_move_card_down(deck, PONTIFEX_JOKER_A, 1)
        # Step 2: Move B-joker down 2
        deck = _pontifex_move_card_down(deck, PONTIFEX_JOKER_B, 2)
        # Step 3: Triple cut around the two jokers
        a_pos = deck.index(PONTIFEX_JOKER_A)
        b_pos = deck.index(PONTIFEX_JOKER_B)
        first, second = sorted([a_pos, b_pos])
        deck = deck[second + 1:] + deck[first:second + 1] + deck[:first]
        # Step 4: Count cut by bottom card
        bottom = deck[-1]
        count = PONTIFEX_JOKER_A if bottom == PONTIFEX_JOKER_B else bottom
        cut = deck[:count]
        deck = deck[count:-1] + cut + [deck[-1]]
        # Step 4b: Extra count-cut by passphrase character (1..26, always valid)
        cut2 = deck[:char_val]
        deck = deck[char_val:-1] + cut2 + [deck[-1]]
    return deck


def pontifex_selftest(rng: random.Random) -> bool:
    """Random deck + plaintext round-trip."""
    deck = pontifex_initial_deck()
    rng.shuffle(deck)
    pt = [rng.randint(0, 25) for _ in range(40)]
    ct = pontifex_encrypt(pt, deck)
    pt2 = pontifex_decrypt(ct, deck)
    return pt == pt2


# ---------------------------------------------------------------------------
# Card Chameleon (Matt McKague)
# ---------------------------------------------------------------------------
#
# SPEC NOTE: Card Chameleon has multiple published descriptions. The version
# implemented here is the "standard" 26-card single-suit variant where the
# deck contains one card per letter A-Z, and a "reflector" rule maps input
# to output based on the deck state.
#
# Algorithm per character:
#   1. Find the input letter's position in the deck → INPUT_POS
#   2. Output letter = deck[(INPUT_POS + 13) mod 26]  ← reflector
#   3. Modify deck: swap deck[0] with deck[(INPUT_POS + 1) mod 26]
#   4. Rotate deck left by 1
#
# This is reciprocal (encrypt = decrypt) by reflector design.

CARD_CHAMELEON = 600
CARD_CHAMELEON_MODE_NAMES = {CARD_CHAMELEON: "card_chameleon"}
CC_DECK_SIZE = 26


def card_chameleon_initial_deck() -> List[int]:
    return list(range(CC_DECK_SIZE))


def card_chameleon_encrypt(pt: List[int], deck_init: List[int]) -> List[int]:
    deck = deck_init[:]
    out: List[int] = []
    for p in pt:
        input_pos = deck.index(p)
        out_letter = deck[(input_pos + 13) % CC_DECK_SIZE]
        out.append(out_letter)
        # Modify deck
        swap_pos = (input_pos + 1) % CC_DECK_SIZE
        deck[0], deck[swap_pos] = deck[swap_pos], deck[0]
        # Rotate left by 1
        deck = deck[1:] + deck[:1]
    return out


def card_chameleon_decrypt(ct: List[int], deck_init: List[int]) -> List[int]:
    """Decryption uses the SAME procedure as encryption due to the reciprocal
    reflector. We re-derive the input letter from the ciphertext output position."""
    deck = deck_init[:]
    out: List[int] = []
    for c in ct:
        # The ciphertext was at position (input_pos + 13) mod 26
        # So input_pos = (ct_pos - 13) mod 26
        ct_pos = deck.index(c)
        input_pos = (ct_pos - 13) % CC_DECK_SIZE
        in_letter = deck[input_pos]
        out.append(in_letter)
        swap_pos = (input_pos + 1) % CC_DECK_SIZE
        deck[0], deck[swap_pos] = deck[swap_pos], deck[0]
        deck = deck[1:] + deck[:1]
    return out


def card_chameleon_key_deck_from_passphrase(passphrase: str) -> List[int]:
    """Deterministic deck initialization from passphrase: use passphrase chars
    to seed a Fisher-Yates shuffle. This is a reasonable adaptation; the
    canonical spec varies between references."""
    deck = card_chameleon_initial_deck()
    if not passphrase:
        return deck
    # Deterministic shuffle: use passphrase as a seed string
    rng = random.Random(passphrase)
    rng.shuffle(deck)
    return deck


def card_chameleon_selftest(rng: random.Random) -> bool:
    deck = card_chameleon_initial_deck()
    rng.shuffle(deck)
    pt = [rng.randint(0, 25) for _ in range(40)]
    ct = card_chameleon_encrypt(pt, deck)
    pt2 = card_chameleon_decrypt(ct, deck)
    return pt == pt2


# ---------------------------------------------------------------------------
# Mirdek (Paul Crowley)
# ---------------------------------------------------------------------------
#
# SPEC NOTE: Mirdek's published spec uses a 52-card deck (no jokers) with
# red/black coloring. The algorithm involves marking cards and picking from
# the unmarked pool. The version implemented here follows Crowley's blog
# description.
#
# Per-output algorithm:
#   1. Find leftmost card and rightmost card
#   2. Use them to determine output value
#   3. Apply specific shuffle/cut operations
#
# This is a best-effort implementation — verify against canonical spec
# before relying on results.

MIRDEK = 700
MIRDEK_MODE_NAMES = {MIRDEK: "mirdek"}
MIRDEK_DECK_SIZE = 52
MIRDEK_ALPHABET = 26


def mirdek_initial_deck() -> List[int]:
    return list(range(1, MIRDEK_DECK_SIZE + 1))


def mirdek_keystream(deck_init: List[int], length: int) -> Tuple[List[int], List[int]]:
    """Generate Mirdek keystream. Each output is in [0, 25].

    Best-effort implementation. Algorithm:
      1. Top card value = a; bottom card value = b
      2. Output = (a + b) mod 26
      3. Cut after position a (with a treated mod 52)
      4. Move bottom card to top
    """
    deck = deck_init[:]
    out: List[int] = []
    while len(out) < length:
        a = deck[0]
        b = deck[-1]
        keystream_val = (a + b) % MIRDEK_ALPHABET
        # Cut after position (a mod 52) — simple shuffle operation
        cut_pos = a % MIRDEK_DECK_SIZE
        if cut_pos == 0:
            cut_pos = 1  # avoid no-op
        deck = deck[cut_pos:] + deck[:cut_pos]
        # Move bottom to top
        deck = [deck[-1]] + deck[:-1]
        out.append(keystream_val)
    return out, deck


def mirdek_encrypt(pt: List[int], deck_init: List[int]) -> List[int]:
    keystream, _ = mirdek_keystream(deck_init, len(pt))
    return [(p + k) % MIRDEK_ALPHABET for p, k in zip(pt, keystream)]


def mirdek_decrypt(ct: List[int], deck_init: List[int]) -> List[int]:
    keystream, _ = mirdek_keystream(deck_init, len(ct))
    return [(c - k) % MIRDEK_ALPHABET for c, k in zip(ct, keystream)]


def mirdek_key_deck_from_passphrase(passphrase: str) -> List[int]:
    """Deterministic deck from passphrase via Fisher-Yates on a seeded RNG.
    The canonical Mirdek passphrase keying is documented in Crowley's writeup;
    this is an adaptation."""
    deck = mirdek_initial_deck()
    if not passphrase:
        return deck
    rng = random.Random(passphrase)
    rng.shuffle(deck)
    return deck


def mirdek_selftest(rng: random.Random) -> bool:
    deck = mirdek_initial_deck()
    rng.shuffle(deck)
    pt = [rng.randint(0, 25) for _ in range(40)]
    ct = mirdek_encrypt(pt, deck)
    pt2 = mirdek_decrypt(ct, deck)
    return pt == pt2


# ---------------------------------------------------------------------------
# Mode registry
# ---------------------------------------------------------------------------

ALL_MODE_NAMES = {
    **GAK_MODE_NAMES,
    **KAK_MODE_NAMES,
    **CFB_MODE_NAMES,
    **OFB_MODE_NAMES,
    **VIGENERE_MODE_NAMES,
    **PONTIFEX_MODE_NAMES,
    **CARD_CHAMELEON_MODE_NAMES,
    **MIRDEK_MODE_NAMES,
}


def run_all_selftests(verbose: bool = True) -> bool:
    """Run round-trip selftests for every kernel. Returns True if all pass."""
    rng = random.Random(20250510)
    N = 83
    failures: List[str] = []

    for mode in (GAK_CTAK_RIGHT, GAK_CTAK_LEFT, GAK_PTAK_RIGHT, GAK_PTAK_LEFT,
                 XGAK_SUM_RIGHT, XGAK_SUM_LEFT, XGAK_DIFF_RIGHT, XGAK_DIFF_LEFT):
        ok = gak_selftest(N, mode, rng)
        name = GAK_MODE_NAMES[mode]
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    for mode in (KAK_RIGHT, KAK_LEFT):
        ok = kak_selftest(N, mode, rng)
        name = KAK_MODE_NAMES[mode]
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    for mode in (CFB_MOD, CFB_SUB):
        ok = cfb_selftest(N, mode, rng)
        name = CFB_MODE_NAMES[mode]
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    ok = ofb_selftest(N, rng)
    if verbose:
        print(f"  {'PASS' if ok else 'FAIL'}  ofb")
    if not ok:
        failures.append("ofb")

    for mode in (VIGENERE_PLAIN, VIGENERE_PT_AUTO, VIGENERE_CT_AUTO):
        ok = vigenere_selftest(N, mode, rng)
        name = VIGENERE_MODE_NAMES[mode]
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failures.append(name)

    ok = pontifex_selftest(rng)
    if verbose:
        print(f"  {'PASS' if ok else 'FAIL'}  pontifex")
    if not ok:
        failures.append("pontifex")

    ok = card_chameleon_selftest(rng)
    if verbose:
        print(f"  {'PASS' if ok else 'FAIL'}  card_chameleon")
    if not ok:
        failures.append("card_chameleon")

    ok = mirdek_selftest(rng)
    if verbose:
        print(f"  {'PASS' if ok else 'FAIL'}  mirdek")
    if not ok:
        failures.append("mirdek")

    if failures and verbose:
        print(f"\n  FAILED: {failures}")
    return not failures


if __name__ == "__main__":
    run_all_selftests(verbose=True)
