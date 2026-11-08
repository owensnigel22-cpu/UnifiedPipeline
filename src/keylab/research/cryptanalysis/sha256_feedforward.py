"""Directly unwind SHA-256's final Davies-Meyer feed-forward addition."""

from __future__ import annotations

from collections.abc import Sequence

_WORD_MASK = 0xFFFFFFFF
SHA256_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


def unwind_feed_forward(
    final_hash: bytes | Sequence[int],
    iv: Sequence[int] = SHA256_IV,
) -> tuple[int, ...]:
    """Recover the pre-feed-forward 8-word compression state.

    ``final_hash`` may be a 32-byte SHA-256 digest or eight unsigned 32-bit
    words. ``iv`` is the 8-word chaining state supplied to the final compression
    block (the standard SHA-256 IV only for a one-block padded message).

    This reverses just the modular additions ``H[i] = W[i] + IV[i]``. It does
    not invert the 64 SHA-256 rounds or recover a message.
    """
    if isinstance(final_hash, bytes):
        if len(final_hash) != 32:
            raise ValueError("final_hash must be 32 bytes or eight 32-bit words")
        final_words = tuple(
            int.from_bytes(final_hash[index : index + 4], "big")
            for index in range(0, 32, 4)
        )
    else:
        final_words = tuple(final_hash)
        if len(final_words) != 8:
            raise ValueError("final_hash must be 32 bytes or eight 32-bit words")

    initial_words = tuple(iv)
    if len(initial_words) != 8:
        raise ValueError("iv must contain exactly eight 32-bit words")
    if any(type(word) is not int or not 0 <= word <= _WORD_MASK for word in final_words):
        raise ValueError("final_hash words must be unsigned 32-bit integers")
    if any(type(word) is not int or not 0 <= word <= _WORD_MASK for word in initial_words):
        raise ValueError("iv words must be unsigned 32-bit integers")
    return tuple((final - initial) & _WORD_MASK for final, initial in zip(final_words, initial_words))


__all__ = ["SHA256_IV", "unwind_feed_forward"]
