"""eyesieve_hypothesis.py — the Hypothesis abstraction.

A Hypothesis bundles a single, executable theory configuration:

  input_binding   — Source resolving to a merged ciphertext
  key_binding     — Source resolving to a key source
  key_derivation  — transforms the key source into the effective key
  cipher          — cipher to apply to (input, effective_key)

execute(corpus) returns the candidate plaintext.

Frozen dataclass: hashable, picklable, multiprocessing-safe.

Errors from underlying modules (SourceError, KeyDerivError, CipherError)
PROPAGATE — the sieve catches them at the boundary; we don't swallow here.
"""

from __future__ import annotations
from dataclasses import dataclass

import eyesieve_ciphers as eci
import eyesieve_corpus as ec
import eyesieve_keyderiv as ekd
import eyesieve_sources as es

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
RuneSeq = tuple[int, ...]


class HypothesisError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: hypothesis :: {msg}")


@dataclass(frozen=True)
class Hypothesis:
    input_binding: es.Source
    key_binding: es.Source
    key_derivation: ekd.KeyDerivation
    cipher: eci.Cipher

    @property
    def name(self) -> str:
        return (f"input={self.input_binding.name} | "
                f"key={self.key_binding.name} | "
                f"derive={self.key_derivation.name} | "
                f"cipher={self.cipher.name}")

    def execute(self, corpus: ec.Corpus) -> RuneSeq:
        merged_ct = self.input_binding.resolve(corpus)
        key_source = self.key_binding.resolve(corpus)
        effective_key = self.key_derivation.derive(key_source, corpus)
        return self.cipher.decrypt(merged_ct, effective_key)

    def execute_with_intermediates(self, corpus: ec.Corpus) -> dict[str, RuneSeq]:
        merged_ct = self.input_binding.resolve(corpus)
        key_source = self.key_binding.resolve(corpus)
        effective_key = self.key_derivation.derive(key_source, corpus)
        candidate = self.cipher.decrypt(merged_ct, effective_key)
        return {
            "merged_ct": merged_ct,
            "key_source": key_source,
            "effective_key": effective_key,
            "candidate": candidate,
        }
