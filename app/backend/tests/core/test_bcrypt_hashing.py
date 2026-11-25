"""Tests for password hashing — ``hash_password`` / ``verify_password``.

Both functions live in ``app.core.security`` and call the ``bcrypt`` package
directly (passlib was removed for Python 3.12 compatibility).

Coverage:
  hash_password: returns a str in bcrypt format with an adequate cost factor
    and a fresh salt per call
  verify_password: True / False results, case sensitivity
  Round-trip, edge cases (empty, spaces, special characters, Unicode, 72 bytes)
  Security properties: the hash does not contain the plaintext; unique salts
"""

from __future__ import annotations

import re

import pytest

from app.core.security import hash_password, verify_password

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KNOWN_PASSWORD = "correct"
_KNOWN_BCRYPT_PATTERN = re.compile(r"^\$2[ab]?\$(\d+)\$.{53}$")
_MIN_ROUNDS = 10  # OWASP minimum work factor for bcrypt

# ---------------------------------------------------------------------------
# hash_password — return type and format
# ---------------------------------------------------------------------------


class TestHashPasswordReturnType:
    """hash_password must return a non-empty string."""

    def test_returns_str(self) -> None:
        result = hash_password("anypassword")
        assert isinstance(result, str)

    def test_returns_non_empty_string(self) -> None:
        result = hash_password("anypassword")
        assert result != ""

    def test_returns_str_for_empty_input(self) -> None:
        result = hash_password("")
        assert isinstance(result, str)


class TestHashPasswordBcryptFormat:
    """hash_password must produce output in the bcrypt hash format."""

    def test_hash_starts_with_bcrypt_identifier(self) -> None:
        """bcrypt hashes begin with $2b$ (or the older $2a$ variant)."""
        h = hash_password("password123")
        assert h.startswith(("$2b$", "$2a$", "$2y$"))

    def test_hash_matches_bcrypt_regex(self) -> None:
        """Full hash must conform to the bcrypt output format."""
        h = hash_password("password123")
        assert _KNOWN_BCRYPT_PATTERN.match(h), f"Hash '{h}' does not match bcrypt format"

    def test_hash_cost_factor_is_adequate(self) -> None:
        """The cost factor embedded in the hash string must be at least 10."""
        h = hash_password("password123")
        # $2b$<cost>$<salt+digest>
        assert int(h.split("$")[2]) >= _MIN_ROUNDS

    def test_hash_total_length(self) -> None:
        """A bcrypt hash is always exactly 60 characters long."""
        h = hash_password("password123")
        assert len(h) == 60, f"Expected length 60, got {len(h)}: {h}"

    def test_hash_algorithm_identifier_is_2b(self) -> None:
        """Passlib bcrypt must use the '2b' algorithm variant by default."""
        h = hash_password("password123")
        parts = h.split("$")
        assert parts[1] == "2b", f"Expected '2b' algorithm, got '{parts[1]}'"


# ---------------------------------------------------------------------------
# hash_password — uniqueness / salt
# ---------------------------------------------------------------------------


class TestHashPasswordUniqueness:
    """Each call must produce a unique hash (random salt)."""

    def test_same_password_produces_different_hashes(self) -> None:
        h1 = hash_password("mypassword")
        h2 = hash_password("mypassword")
        assert h1 != h2

    def test_three_hashes_are_all_distinct(self) -> None:
        hashes = {hash_password("shared") for _ in range(3)}
        assert len(hashes) == 3

    def test_salt_portion_differs_between_calls(self) -> None:
        """The 22-character salt embedded after the cost must differ."""
        h1 = hash_password("mypassword")
        h2 = hash_password("mypassword")
        # Salt is the first 22 chars of the last segment
        salt1 = h1.split("$")[-1][:22]
        salt2 = h2.split("$")[-1][:22]
        assert salt1 != salt2


# ---------------------------------------------------------------------------
# verify_password — correct and incorrect passwords
# ---------------------------------------------------------------------------


class TestVerifyPasswordCorrect:
    """verify_password must return True when the plaintext matches the hash."""

    def test_correct_password_returns_true(self) -> None:
        h = hash_password(_KNOWN_PASSWORD)
        assert verify_password(_KNOWN_PASSWORD, h) is True

    def test_verify_returns_bool_true(self) -> None:
        h = hash_password("testpass")
        result = verify_password("testpass", h)
        assert type(result) is bool

    def test_correct_password_for_typical_value(self) -> None:
        pw = "Str0ng!P@ss#2025"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_correct_empty_password(self) -> None:
        h = hash_password("")
        assert verify_password("", h) is True


class TestVerifyPasswordWrong:
    """verify_password must return False when the plaintext does not match."""

    def test_wrong_password_returns_false(self) -> None:
        h = hash_password("rightpassword")
        assert verify_password("wrongpassword", h) is False

    def test_verify_returns_bool_false(self) -> None:
        h = hash_password("testpass")
        result = verify_password("wrongpass", h)
        assert type(result) is bool

    def test_empty_string_vs_non_empty_hash_returns_false(self) -> None:
        h = hash_password("notempty")
        assert verify_password("", h) is False

    def test_non_empty_vs_empty_string_hash_returns_false(self) -> None:
        h = hash_password("")
        assert verify_password("notempty", h) is False

    def test_case_sensitivity_lowercase_vs_upper(self) -> None:
        h = hash_password("Password")
        assert verify_password("password", h) is False

    def test_case_sensitivity_upper_vs_lowercase(self) -> None:
        h = hash_password("password")
        assert verify_password("Password", h) is False

    def test_extra_space_makes_wrong(self) -> None:
        h = hash_password("hello")
        assert verify_password("hello ", h) is False

    def test_leading_space_makes_wrong(self) -> None:
        h = hash_password("hello")
        assert verify_password(" hello", h) is False

    def test_substring_of_correct_password_fails(self) -> None:
        h = hash_password("mypassword")
        assert verify_password("mypass", h) is False

    def test_completely_different_password_fails(self) -> None:
        h = hash_password("alpha")
        assert verify_password("beta", h) is False


# ---------------------------------------------------------------------------
# Round-trip tests (hash_password → verify_password)
# ---------------------------------------------------------------------------


class TestBcryptRoundTrip:
    """Hashing and then verifying must produce consistent results."""

    def test_round_trip_correct_password(self) -> None:
        h = hash_password("roundtrip")
        assert verify_password("roundtrip", h) is True

    def test_round_trip_wrong_password(self) -> None:
        h = hash_password("roundtrip")
        assert verify_password("different", h) is False

    def test_two_hashes_of_same_password_both_verify(self) -> None:
        """Unique salts must not break verification for either hash."""
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2
        assert verify_password("same", h1) is True
        assert verify_password("same", h2) is True

    def test_hash_A_does_not_verify_with_hash_B(self) -> None:
        """A hash of 'foo' must not verify the password 'bar'."""
        h_foo = hash_password("foo")
        h_bar = hash_password("bar")
        assert verify_password("bar", h_foo) is False
        assert verify_password("foo", h_bar) is False

    @pytest.mark.parametrize(
        "password",
        [
            "short",
            "a" * 32,
            "MixedCase_123!",
            "spaces in between",
            "unicode: café naïve résumé",
            "special: !@#$%^&*()-_=+[]{}|;':\",./<>?",
        ],
    )
    def test_parametrized_round_trips(self, password: str) -> None:
        """A variety of password strings must survive a hash–verify round-trip."""
        h = hash_password(password)
        assert verify_password(password, h) is True
        assert verify_password(password + "x", h) is False


# ---------------------------------------------------------------------------
# Edge-case passwords
# ---------------------------------------------------------------------------


class TestHashPasswordEdgeCases:
    """hash_password must handle unusual but valid password strings."""

    def test_empty_string_produces_bcrypt_hash(self) -> None:
        h = hash_password("")
        assert h.startswith(("$2b$", "$2a$", "$2y$"))

    def test_spaces_only_password(self) -> None:
        h = hash_password("   ")
        assert h.startswith(("$2b$", "$2a$", "$2y$"))
        assert verify_password("   ", h) is True

    def test_special_chars_password(self) -> None:
        pw = r"!@#$%^&*()-_=+[]{}|;':\",./<>?"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_unicode_password(self) -> None:
        pw = "pässwörD_ñoño"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_72_byte_password(self) -> None:
        """Passwords at exactly bcrypt's 72-byte limit must be hashed and verified."""
        pw = "a" * 72
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_newline_in_password(self) -> None:
        pw = "pass\nword"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_null_byte_in_password(self) -> None:
        """Passlib bcrypt truncates at null bytes; hashing must at least not crash."""
        try:
            h = hash_password("pass\x00word")
            assert isinstance(h, str)
        except (ValueError, TypeError):
            # Some backends reject null bytes — that is also acceptable behaviour
            pass


# ---------------------------------------------------------------------------
# Security properties
# ---------------------------------------------------------------------------


class TestBcryptSecurityProperties:
    """High-level security invariants for the bcrypt implementation."""

    def test_hash_does_not_contain_plaintext(self) -> None:
        pw = "supersecretpassword"
        h = hash_password(pw)
        assert pw not in h

    def test_same_password_different_salts(self) -> None:
        """Identical passwords must produce completely different hashes."""
        hashes = [hash_password("samepassword") for _ in range(5)]
        assert len(set(hashes)) == 5, "Expected 5 unique hashes, got duplicates"

    def test_different_passwords_produce_different_hashes(self) -> None:
        h1 = hash_password("alpha_pass")
        h2 = hash_password("beta_pass")
        assert h1 != h2

    def test_wrong_password_consistently_fails(self) -> None:
        """verify_password must consistently return False for a wrong password."""
        h = hash_password("correct")
        for _ in range(3):
            assert verify_password("wrong", h) is False

    def test_correct_password_consistently_passes(self) -> None:
        h = hash_password("correct")
        for _ in range(3):
            assert verify_password("correct", h) is True
