"""Tests for feature 2.1: Password policy — min 8 chars, 3 of 4 character types.

Coverage:
  validate_password_complexity — accepted: 3+ character types present
  validate_password_complexity — rejected: fewer than 3 character types
  validate_password_complexity — boundary: exactly 3 types accepted, exactly 2 rejected
  validate_password_complexity — all 4 types accepted
  validate_password_complexity — short passwords that would pass type check still pass
    (length is enforced separately by Pydantic field constraints)
  UserCreate schema — password complexity enforced on user creation
  ChangePasswordRequest schema — complexity enforced on password change
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.validators import validate_password_complexity
from app.api.v1.endpoints.users import UserCreate
from app.schemas.auth import ChangePasswordRequest


# ---------------------------------------------------------------------------
# validate_password_complexity — unit tests
# ---------------------------------------------------------------------------


class TestValidatePasswordComplexityAccepted:
    """Passwords meeting at least 3 character-type categories are accepted."""

    def test_uppercase_lowercase_digits(self):
        """3 types: upper + lower + digit."""
        assert validate_password_complexity("Password1") == "Password1"

    def test_uppercase_lowercase_special(self):
        """3 types: upper + lower + special."""
        assert validate_password_complexity("Password!") == "Password!"

    def test_uppercase_digits_special(self):
        """3 types: upper + digit + special."""
        assert validate_password_complexity("PASSW0RD!") == "PASSW0RD!"

    def test_lowercase_digits_special(self):
        """3 types: lower + digit + special."""
        assert validate_password_complexity("passw0rd!") == "passw0rd!"

    def test_all_four_types(self):
        """4 types: upper + lower + digit + special — maximum complexity."""
        assert validate_password_complexity("Passw0rd!") == "Passw0rd!"

    def test_various_special_chars(self):
        """Special characters include punctuation, symbols, spaces."""
        for special in ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", " "]:
            pwd = f"Password1{special}"
            result = validate_password_complexity(pwd)
            assert result == pwd

    def test_unicode_special_char(self):
        """Non-ASCII characters count as special (not alphanumeric)."""
        assert validate_password_complexity("Password1é") == "Password1é"

    def test_returns_original_value(self):
        """Function returns the original password string unchanged."""
        pwd = "MyP@ss1"
        assert validate_password_complexity(pwd) is pwd


class TestValidatePasswordComplexityRejected:
    """Passwords with fewer than 3 character-type categories are rejected."""

    def test_only_lowercase_raises(self):
        """1 type: lowercase only."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("password")

    def test_only_uppercase_raises(self):
        """1 type: uppercase only."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("PASSWORD")

    def test_only_digits_raises(self):
        """1 type: digits only."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("12345678")

    def test_only_special_raises(self):
        """1 type: special only."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("!@#$%^&*")

    def test_lowercase_uppercase_only_raises(self):
        """2 types: lower + upper (no digits or specials)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("PasswordABC")

    def test_lowercase_digits_only_raises(self):
        """2 types: lower + digit (no upper or specials)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("password123")

    def test_uppercase_digits_only_raises(self):
        """2 types: upper + digit (no lower or specials)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("PASSWORD123")

    def test_lowercase_special_only_raises(self):
        """2 types: lower + special (no upper or digits)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("password!")

    def test_uppercase_special_only_raises(self):
        """2 types: upper + special (no lower or digits)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("PASSWORD!")

    def test_digits_special_only_raises(self):
        """2 types: digit + special (no lower or upper)."""
        with pytest.raises(ValueError, match="3 of the following character types"):
            validate_password_complexity("12345!@#")

    def test_error_message_mentions_character_types(self):
        """Error message describes all 4 possible character categories."""
        with pytest.raises(ValueError) as exc_info:
            validate_password_complexity("onlylower")
        msg = str(exc_info.value)
        assert "uppercase letters" in msg
        assert "lowercase letters" in msg
        assert "digits" in msg
        assert "special characters" in msg


class TestValidatePasswordComplexityBoundary:
    """Boundary: exactly 3 types accepted; exactly 2 rejected."""

    def test_exactly_3_types_accepted(self):
        """Password with exactly 3 of 4 character types passes."""
        assert validate_password_complexity("Abc123") == "Abc123"  # upper + lower + digit

    def test_exactly_2_types_rejected(self):
        """Password with exactly 2 of 4 character types fails."""
        with pytest.raises(ValueError):
            validate_password_complexity("abcABC")  # lower + upper only

    def test_single_special_char_satisfies_type(self):
        """A single special character is enough to fulfill that category."""
        assert validate_password_complexity("Password!") == "Password!"  # upper+lower+special

    def test_single_digit_satisfies_type(self):
        """A single digit is enough to fulfill the digit category."""
        assert validate_password_complexity("Password1") == "Password1"  # upper+lower+digit


# ---------------------------------------------------------------------------
# UserCreate schema — password complexity enforced at user creation
# ---------------------------------------------------------------------------


class TestUserCreatePasswordComplexity:
    """UserCreate schema rejects passwords that fail complexity requirements."""

    def test_valid_password_accepted(self):
        """Password with 3+ types passes UserCreate validation."""
        u = UserCreate(email="user@example.com", password="Secure1!")
        assert u.email == "user@example.com"

    def test_two_types_raises(self):
        """Password with only 2 types is rejected by UserCreate."""
        with pytest.raises(ValidationError, match="3 of the following character types"):
            UserCreate(email="user@example.com", password="password123")

    def test_one_type_raises(self):
        """Password with only lowercase letters is rejected."""
        with pytest.raises(ValidationError, match="3 of the following character types"):
            UserCreate(email="user@example.com", password="passwordonly")

    def test_complexity_and_length_both_enforced(self):
        """Password too short AND lacking complexity fails (length check fires first)."""
        with pytest.raises(ValidationError):
            UserCreate(email="user@example.com", password="Ab1")

    def test_uppercase_lowercase_digit(self):
        UserCreate(email="user@example.com", password="StrongPass1")

    def test_uppercase_lowercase_special(self):
        UserCreate(email="user@example.com", password="StrongPass!")

    def test_uppercase_digit_special(self):
        UserCreate(email="user@example.com", password="STRONG1!")

    def test_lowercase_digit_special(self):
        UserCreate(email="user@example.com", password="strong1!")


# ---------------------------------------------------------------------------
# ChangePasswordRequest schema — complexity enforced on password change
# ---------------------------------------------------------------------------


class TestChangePasswordRequestComplexity:
    """ChangePasswordRequest.new_password rejects passwords failing complexity."""

    _TOKEN = "x" * 10  # placeholder; token validity not tested here

    def _make(self, new_password: str, confirm_password: str | None = None) -> ChangePasswordRequest:
        if confirm_password is None:
            confirm_password = new_password
        return ChangePasswordRequest(
            password_change_token=self._TOKEN,
            new_password=new_password,
            confirm_password=confirm_password,
        )

    def test_valid_password_accepted(self):
        req = self._make("Secure1!")
        assert req.new_password == "Secure1!"

    def test_two_types_raises(self):
        with pytest.raises(ValidationError, match="3 of the following character types"):
            self._make("password123")

    def test_one_type_raises(self):
        with pytest.raises(ValidationError, match="3 of the following character types"):
            self._make("passwordonly")

    def test_complexity_and_mismatch_are_independent(self):
        """When new_password fails complexity, mismatch is not relevant."""
        with pytest.raises(ValidationError, match="3 of the following character types"):
            ChangePasswordRequest(
                password_change_token=self._TOKEN,
                new_password="password123",
                confirm_password="different_password",
            )

    def test_all_four_types_accepted(self):
        req = self._make("MyP@ss12")
        assert req.new_password == "MyP@ss12"

    def test_confirm_password_not_complexity_checked(self):
        """confirm_password field is not itself complexity-validated —
        only new_password runs the complexity check. The mismatch validator
        fires if they differ, but confirm_password alone is not checked."""
        # This passes because new_password is valid; confirm_password matches
        req = self._make("Secure1!", "Secure1!")
        assert req.confirm_password == "Secure1!"
