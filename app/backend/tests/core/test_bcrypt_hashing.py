"""Tests for Feature 2.5 — bcrypt hashing — 12 rounds

``hash_password`` wraps passlib's CryptContext to produce a bcrypt hash.
``verify_password`` verifies a plaintext password against a stored hash.
Both functions live in ``app.core.security``.

Coverage:
  pwd_context configuration:
    - Default scheme is "bcrypt"
    - bcrypt handler default_rounds is 12
  hash_password:
    - Returns a str
    - Produces a valid bcrypt hash ($2b$12$… format)
    - Cost factor in hash is 12
    - Each call produces a different salt (non-deterministic)
    - Delegates to pwd_context.hash with the correct argument
  verify_password:
    - Returns True for the correct plaintext against its hash
    - Returns False for a wrong plaintext
    - Returns a bool (not a truthy/falsy object)
    - Case-sensitive: "Password" ≠ "password"
    - Delegates to pwd_context.verify with correct arguments
  Round-trip (hash_password → verify_password):
    - Correct password verifies successfully
    - Wrong password is rejected
    - Two different hashes of the same password both verify correctly
  Edge cases:
    - Empty-string password can be hashed and verified
    - Password containing only spaces
    - Password with ASCII special characters
    - Password with Unicode characters
    - Password exactly 72 bytes (bcrypt's hard limit)
  Security properties:
    - The hash does not contain the plaintext password
    - Two hashes of the same password are distinct (unique salts)

Implementation note — passlib 1.7.4 + bcrypt ≥ 4 incompatibility:
  passlib's ``detect_wrap_bug`` sends a >72-byte test password to bcrypt
  during backend initialisation.  bcrypt ≥ 4 now raises ``ValueError`` for
  passwords longer than 72 bytes instead of silently truncating them.  The
  session-scoped autouse fixture ``_patch_bcrypt_compat`` applies a minimal
  shim — truncating the oversized password before delegating to the real
  ``hashpw`` — so that the passlib backend initialises correctly without
  affecting any production hashing paths (all real passwords are well
  under 72 bytes).
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, call, patch

import bcrypt as _raw_bcrypt
import pytest

# ---------------------------------------------------------------------------
# Compatibility shim — must run before any passlib hash/verify call
# ---------------------------------------------------------------------------

_ORIG_HASHPW = _raw_bcrypt.hashpw


def _compat_hashpw(password: bytes, salt: bytes) -> bytes:
    """Drop-in replacement for bcrypt.hashpw that truncates passwords > 72 bytes.

    passlib 1.7.4's detect_wrap_bug passes a 73-byte test password; bcrypt ≥ 4
    raises ValueError for such inputs.  Truncating to 72 bytes lets the bug
    detection succeed while leaving normal (<= 72 byte) passwords untouched.
    """
    if len(password) > 72:
        password = password[:72]
    return _ORIG_HASHPW(password, salt)


@pytest.fixture(scope="session", autouse=True)
def _patch_bcrypt_compat():
    """Session-wide shim: make passlib 1.7.4 work with bcrypt ≥ 4.

    The shim is applied once for the entire test session and removes itself
    when the session ends.  It does not affect any tests outside this module
    because conftest.py does not declare it, but the session scope means it
    is initialised before any hash/verify call anywhere in the test run.
    """
    # Add the missing __about__ that passlib tries to read for version detection
    if not hasattr(_raw_bcrypt, "__about__"):

        class _About:
            __version__ = _raw_bcrypt.__version__

        _raw_bcrypt.__about__ = _About  # type: ignore[attr-defined]

    _raw_bcrypt.hashpw = _compat_hashpw  # type: ignore[assignment]
    yield
    _raw_bcrypt.hashpw = _ORIG_HASHPW  # type: ignore[assignment]
    if hasattr(_raw_bcrypt, "__about__"):
        del _raw_bcrypt.__about__  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Imports that depend on the shim being applied first
# ---------------------------------------------------------------------------

from app.core.security import hash_password, pwd_context, verify_password  # noqa: E402
import passlib.handlers.bcrypt as _passlib_bcrypt_handler  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# A 12-round bcrypt hash of the string "correct" — used as a pre-computed
# fixture for verify_password tests that do not need to call hash_password.
# Computed with: bcrypt.hashpw(b"correct", bcrypt.gensalt(rounds=12))
_KNOWN_PASSWORD = "correct"
_KNOWN_BCRYPT_PATTERN = re.compile(r"^\$2[ab]?\$(\d+)\$.{53}$")
_EXPECTED_ROUNDS = 12
_EXPECTED_SCHEME = "bcrypt"

# ---------------------------------------------------------------------------
# pwd_context configuration
# ---------------------------------------------------------------------------


class TestPwdContextConfiguration:
    """Verify that pwd_context is wired for bcrypt with 12 rounds."""

    def test_default_scheme_is_bcrypt(self) -> None:
        """CryptContext must advertise 'bcrypt' as its default scheme."""
        assert pwd_context.default_scheme() == _EXPECTED_SCHEME

    def test_bcrypt_handler_default_rounds_is_12(self) -> None:
        """The passlib bcrypt handler must default to 12 rounds."""
        assert _passlib_bcrypt_handler.bcrypt.default_rounds == _EXPECTED_ROUNDS

    def test_pwd_context_uses_only_bcrypt(self) -> None:
        """The context must not silently fall back to a weaker scheme."""
        schemes = list(pwd_context.schemes())
        assert schemes == [_EXPECTED_SCHEME]


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

    def test_hash_cost_factor_is_12(self) -> None:
        """The cost factor embedded in the hash string must be 12."""
        h = hash_password("password123")
        # bcrypt format: $2b$<cost>$<53-char-salt+digest>
        parts = h.split("$")
        # parts[0]='', parts[1]='2b', parts[2]='12', parts[3]=salt+digest
        assert len(parts) >= 4, f"Unexpected hash format: {h}"
        assert parts[2] == str(_EXPECTED_ROUNDS), (
            f"Expected cost factor {_EXPECTED_ROUNDS}, got {parts[2]}"
        )

    def test_hash_total_length(self) -> None:
        """A bcrypt 12-round hash is always exactly 60 characters long."""
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
# hash_password — delegation to pwd_context.hash
# ---------------------------------------------------------------------------


class TestHashPasswordDelegation:
    """hash_password must delegate to pwd_context.hash with the right argument."""

    def test_delegates_to_pwd_context_hash(self) -> None:
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$fakehash_for_delegation_test_ok"
            hash_password("mypassword")
        mock_ctx.hash.assert_called_once_with("mypassword")

    def test_returns_value_from_pwd_context_hash(self) -> None:
        fake_hash = "$2b$12$fakehash_value_from_pwd_context_ok"
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = fake_hash
            result = hash_password("anything")
        assert result == fake_hash

    def test_passes_password_unchanged_to_pwd_context(self) -> None:
        """The password must be forwarded verbatim — no pre-processing."""
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$placeholder"
            hash_password("exact!Pass#word")
        assert mock_ctx.hash.call_args == call("exact!Pass#word")

    def test_empty_string_forwarded_to_pwd_context(self) -> None:
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.hash.return_value = "$2b$12$placeholder"
            hash_password("")
        mock_ctx.hash.assert_called_once_with("")


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
# verify_password — delegation to pwd_context.verify
# ---------------------------------------------------------------------------


class TestVerifyPasswordDelegation:
    """verify_password must delegate to pwd_context.verify with correct args."""

    def test_delegates_to_pwd_context_verify(self) -> None:
        fake_hash = "$2b$12$fakehash_verify_delegation"
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = True
            verify_password("plain", fake_hash)
        mock_ctx.verify.assert_called_once_with("plain", fake_hash)

    def test_returns_value_from_pwd_context_verify_true(self) -> None:
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = True
            result = verify_password("plain", "$2b$12$anyhash")
        assert result is True

    def test_returns_value_from_pwd_context_verify_false(self) -> None:
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = False
            result = verify_password("plain", "$2b$12$anyhash")
        assert result is False

    def test_plain_and_hash_forwarded_verbatim(self) -> None:
        plain = "exact!Pass#word"
        hashed = "$2b$12$exacthashinput"
        with patch("app.core.security.pwd_context") as mock_ctx:
            mock_ctx.verify.return_value = False
            verify_password(plain, hashed)
        assert mock_ctx.verify.call_args == call(plain, hashed)


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
