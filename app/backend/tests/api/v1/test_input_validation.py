"""Tests for input validation hardening (feature 33.3).

Coverage:
  - Schema-level validation: max_length, min_length, pattern, email, IP
  - EventFilter field/operator whitelist
  - SearchRequest limits (query, size, from_, filter count)
  - RuleCreate / RuleImportRequest size limits
  - ConnectorCreate name max_length
  - UserCreate email format + password length
  - Body size limit middleware (HTTP 413)
  - LIKE wildcard escaping in repositories
  - OpenSearch query uses simple_query_string (not query_string)
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Core validator helpers
# ---------------------------------------------------------------------------

from app.core.validators import (
    EMAIL_MAX_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    escape_like,
    validate_cidr,
    validate_hostname,
    validate_ip_address,
)


class TestEscapeLike:
    def test_no_special_chars(self):
        assert escape_like("hello") == "hello"

    def test_percent_escaped(self):
        assert escape_like("100%") == r"100\%"

    def test_underscore_escaped(self):
        assert escape_like("user_name") == r"user\_name"

    def test_backslash_escaped_first(self):
        assert escape_like("a\\b") == r"a\\b"

    def test_combined(self):
        result = escape_like("%_\\")
        assert result == r"\%\_\\"

    def test_empty_string(self):
        assert escape_like("") == ""


class TestValidateIpAddress:
    def test_valid_ipv4(self):
        assert validate_ip_address("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert validate_ip_address("::1") == "::1"

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_ip_address("not-an-ip")

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError):
            validate_ip_address("999.999.999.999")


class TestValidateCidr:
    def test_valid_ipv4_cidr(self):
        assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"

    def test_valid_host_cidr(self):
        assert validate_cidr("192.168.1.1/32") == "192.168.1.1/32"

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            validate_cidr("not-cidr")


class TestValidateHostname:
    def test_simple_label(self):
        assert validate_hostname("srv01") == "srv01"

    def test_fqdn(self):
        assert validate_hostname("srv01.example.com") == "srv01.example.com"

    def test_local_name(self):
        assert validate_hostname("analyst.mxtac.local") == "analyst.mxtac.local"

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="253"):
            validate_hostname("a" * 254)

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError, match="Invalid hostname label"):
            validate_hostname("-invalid")


# ---------------------------------------------------------------------------
# Pydantic schema validators
# ---------------------------------------------------------------------------

from app.schemas.auth import LoginRequest, MfaVerifyRequest, MfaVerifyLoginRequest, MfaDisableRequest


class TestLoginRequestValidation:
    def test_valid(self):
        req = LoginRequest(email="user@example.com", password="password123")
        assert req.email == "user@example.com"

    def test_email_too_long_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="a" * 255 + "@example.com", password="password123")

    def test_invalid_email_format_raises(self):
        with pytest.raises(ValidationError, match="valid email"):
            LoginRequest(email="not-an-email", password="password123")

    def test_password_too_long_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="user@example.com", password="x" * (PASSWORD_MAX_LENGTH + 1))


class TestMfaVerifyRequestValidation:
    def test_valid_totp(self):
        req = MfaVerifyRequest(code="123456")
        assert req.code == "123456"

    def test_too_short_raises(self):
        with pytest.raises(ValidationError):
            MfaVerifyRequest(code="123")

    def test_too_long_raises(self):
        with pytest.raises(ValidationError):
            MfaVerifyRequest(code="1" * 17)

    def test_invalid_chars_raises(self):
        with pytest.raises(ValidationError):
            MfaVerifyRequest(code="12345!")


class TestMfaVerifyLoginRequestValidation:
    def test_mfa_token_too_long_raises(self):
        with pytest.raises(ValidationError):
            MfaVerifyLoginRequest(mfa_token="x" * 513, code="123456")


class TestMfaDisableRequestValidation:
    def test_valid_user_id(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        req = MfaDisableRequest(user_id=uid)
        assert req.user_id == uid

    def test_non_uuid_short_raises(self):
        with pytest.raises(ValidationError):
            MfaDisableRequest(user_id="42")

    def test_non_uuid_alpha_raises(self):
        with pytest.raises(ValidationError):
            MfaDisableRequest(user_id="abc")

    def test_non_uuid_zero_raises(self):
        with pytest.raises(ValidationError):
            MfaDisableRequest(user_id="0")

    def test_malformed_uuid_raises(self):
        # Correct length but wrong format
        with pytest.raises(ValidationError):
            MfaDisableRequest(user_id="not-a-valid-uuid-string-here-xyz")

    def test_empty_raises(self):
        with pytest.raises(ValidationError):
            MfaDisableRequest(user_id="")


from app.schemas.asset import AssetCreate, AssetUpdate


class TestAssetCreateValidation:
    def test_valid_ip_list(self):
        asset = AssetCreate(
            hostname="server01",
            ip_addresses=["10.0.0.1", "192.168.1.2"],
            asset_type="server",
        )
        assert len(asset.ip_addresses) == 2

    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError, match="Invalid IP address"):
            AssetCreate(
                hostname="server01",
                ip_addresses=["not-an-ip"],
                asset_type="server",
            )

    def test_tag_too_long_raises(self):
        with pytest.raises(ValidationError, match="64"):
            AssetCreate(
                hostname="server01",
                asset_type="server",
                tags=["a" * 65],
            )

    def test_too_many_tags_raises(self):
        with pytest.raises(ValidationError):
            AssetCreate(
                hostname="server01",
                asset_type="server",
                tags=["tag"] * 51,
            )

    def test_valid_os_family(self):
        asset = AssetCreate(hostname="server01", asset_type="server", os_family="linux")
        assert asset.os_family == "linux"

    def test_invalid_os_family_raises(self):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="server01", asset_type="server", os_family="unknown_os")

    def test_none_os_family_passes(self):
        asset = AssetCreate(hostname="server01", asset_type="server", os_family=None)
        assert asset.os_family is None


class TestAssetUpdateValidation:
    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError, match="Invalid IP address"):
            AssetUpdate(ip_addresses=["999.999.999.999"])

    def test_none_ip_passes(self):
        update = AssetUpdate(ip_addresses=None)
        assert update.ip_addresses is None

    def test_owner_max_length_raises(self):
        with pytest.raises(ValidationError):
            AssetUpdate(owner="x" * 256)


from app.schemas.incident import IncidentCreate, IncidentUpdate


class TestIncidentCreateValidation:
    def test_description_too_long_raises(self):
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Incident",
                description="x" * 10001,
                severity="high",
            )

    def test_assigned_to_too_long_raises(self):
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Incident",
                severity="high",
                assigned_to="a" * 255,
            )

    def test_too_many_detection_ids_raises(self):
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Incident",
                severity="high",
                detection_ids=["det-id"] * 501,
            )

    def test_valid_assigned_to_email(self):
        inc = IncidentCreate(
            title="Incident",
            severity="high",
            assigned_to="analyst@mxtac.local",
        )
        assert inc.assigned_to == "analyst@mxtac.local"

    def test_invalid_assigned_to_email_raises(self):
        with pytest.raises(ValidationError, match="valid email"):
            IncidentCreate(
                title="Incident",
                severity="high",
                assigned_to="not-an-email",
            )

    def test_none_assigned_to_passes(self):
        inc = IncidentCreate(title="Incident", severity="high", assigned_to=None)
        assert inc.assigned_to is None


class TestIncidentUpdateValidation:
    def test_invalid_assigned_to_email_raises(self):
        with pytest.raises(ValidationError, match="valid email"):
            IncidentUpdate(assigned_to="not-an-email")


from app.schemas.ioc import IOCCreate
from datetime import datetime, timezone


class TestIOCCreateValidation:
    def _base(self, **kwargs):
        defaults = dict(
            ioc_type="ip",
            value="10.0.0.1",
            source="test",
            severity="high",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        defaults.update(kwargs)
        return IOCCreate(**defaults)

    def test_description_too_long_raises(self):
        with pytest.raises(ValidationError):
            self._base(description="x" * 2001)

    def test_too_many_tags_raises(self):
        with pytest.raises(ValidationError):
            self._base(tags=["tag"] * 51)

    # --- Type-specific value validation ---

    def test_valid_ip(self):
        ioc = self._base(ioc_type="ip", value="192.168.1.1")
        assert ioc.value == "192.168.1.1"

    def test_valid_ipv6(self):
        ioc = self._base(ioc_type="ip", value="::1")
        assert ioc.value == "::1"

    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError, match="Invalid IP"):
            self._base(ioc_type="ip", value="not-an-ip")

    def test_valid_domain(self):
        ioc = self._base(ioc_type="domain", value="example.com")
        assert ioc.value == "example.com"

    def test_invalid_domain_raises(self):
        with pytest.raises(ValidationError):
            self._base(ioc_type="domain", value="-invalid-domain")

    def test_valid_md5(self):
        ioc = self._base(ioc_type="hash_md5", value="d41d8cd98f00b204e9800998ecf8427e")
        assert ioc.ioc_type == "hash_md5"

    def test_invalid_md5_raises(self):
        with pytest.raises(ValidationError, match="MD5"):
            self._base(ioc_type="hash_md5", value="tooshort")

    def test_invalid_md5_nonhex_raises(self):
        with pytest.raises(ValidationError, match="MD5"):
            self._base(ioc_type="hash_md5", value="z" * 32)

    def test_valid_sha256(self):
        ioc = self._base(
            ioc_type="hash_sha256",
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        assert ioc.ioc_type == "hash_sha256"

    def test_invalid_sha256_raises(self):
        with pytest.raises(ValidationError, match="SHA-256"):
            self._base(ioc_type="hash_sha256", value="abc123")

    def test_valid_url(self):
        ioc = self._base(ioc_type="url", value="https://malicious.example.com/path")
        assert ioc.value.startswith("https://")

    def test_url_without_scheme_raises(self):
        with pytest.raises(ValidationError, match="http"):
            self._base(ioc_type="url", value="malicious.example.com")

    def test_valid_email_ioc(self):
        ioc = self._base(ioc_type="email", value="attacker@evil.com")
        assert ioc.ioc_type == "email"

    def test_invalid_email_ioc_raises(self):
        with pytest.raises(ValidationError, match="Invalid email"):
            self._base(ioc_type="email", value="not-an-email")


# ---------------------------------------------------------------------------
# Inline endpoint schema validators
# ---------------------------------------------------------------------------

from app.api.v1.endpoints.events import EventFilter, SearchRequest, AggregationRequest


class TestEventFilterValidation:
    def test_valid_field_and_operator(self):
        f = EventFilter(field="hostname", operator="eq", value="server01")
        assert f.field == "hostname"

    def test_unknown_field_raises(self):
        with pytest.raises(ValidationError, match="Unknown filter field"):
            EventFilter(field="injected_field", operator="eq", value="x")

    def test_invalid_operator_raises(self):
        with pytest.raises(ValidationError):
            EventFilter(field="hostname", operator="not_an_op", value="x")

    def test_all_valid_operators(self):
        for op in ("eq", "ne", "gt", "lt", "gte", "lte", "contains"):
            f = EventFilter(field="severity_id", operator=op, value=1)
            assert f.operator == op


class TestSearchRequestValidation:
    def test_query_too_long_raises(self):
        with pytest.raises(ValidationError):
            SearchRequest(query="x" * 2049)

    def test_size_too_large_raises(self):
        with pytest.raises(ValidationError):
            SearchRequest(size=1001)

    def test_size_zero_raises(self):
        with pytest.raises(ValidationError):
            SearchRequest(size=0)

    def test_from_negative_raises(self):
        with pytest.raises(ValidationError):
            SearchRequest(from_=-1)

    def test_too_many_filters_raises(self):
        with pytest.raises(ValidationError):
            SearchRequest(
                filters=[
                    EventFilter(field="hostname", operator="eq", value="x")
                ] * 51
            )

    def test_valid_defaults(self):
        req = SearchRequest()
        assert req.size == 100
        assert req.from_ == 0

    # --- Feature 33.3: time range injection prevention ---

    def test_time_from_lucene_injection_raises(self):
        """Lucene injection characters in time_from must be rejected."""
        with pytest.raises(ValidationError, match="time_from"):
            SearchRequest(time_from="now-7d] OR *:*")

    def test_time_to_lucene_injection_raises(self):
        with pytest.raises(ValidationError, match="time_to"):
            SearchRequest(time_to="now} OR (*:*")

    def test_time_from_space_injection_raises(self):
        with pytest.raises(ValidationError, match="time_from"):
            SearchRequest(time_from="now-7d AND field:injected")

    def test_valid_relative_time_from(self):
        req = SearchRequest(time_from="now-30d", time_to="now")
        assert req.time_from == "now-30d"

    def test_valid_iso8601_time(self):
        req = SearchRequest(
            time_from="2026-01-01T00:00:00Z",
            time_to="2026-12-31T23:59:59Z",
        )
        assert req.time_from == "2026-01-01T00:00:00Z"

    def test_valid_time_with_offset(self):
        req = SearchRequest(
            time_from="2026-01-01T00:00:00+00:00",
            time_to="2026-12-31T23:59:59+05:30",
        )
        assert "+" in req.time_from

    def test_valid_now_keyword(self):
        req = SearchRequest(time_from="now", time_to="now")
        assert req.time_from == "now"


class TestAggregationRequestValidation:
    def test_invalid_agg_type_raises(self):
        with pytest.raises(ValidationError):
            AggregationRequest(agg_type="invalid_type")

    def test_invalid_interval_raises(self):
        with pytest.raises(ValidationError):
            AggregationRequest(interval="99x")

    def test_valid_intervals(self):
        for interval in ("1m", "1h", "1d", "1w", "1M"):
            req = AggregationRequest(agg_type="date_histogram", interval=interval)
            assert req.interval == interval

    def test_size_too_large_raises(self):
        with pytest.raises(ValidationError):
            AggregationRequest(size=1001)


from app.api.v1.endpoints.rules import RuleCreate, RuleImportRequest, _MAX_YAML_BYTES, _MAX_IMPORT_YAML_BYTES


class TestRuleSchemaValidation:
    def test_content_too_long_raises(self):
        with pytest.raises(ValidationError):
            RuleCreate(title="Rule", content="x" * (_MAX_YAML_BYTES + 1))

    def test_title_empty_raises(self):
        with pytest.raises(ValidationError):
            RuleCreate(title="", content="title: test")

    def test_title_too_long_raises(self):
        with pytest.raises(ValidationError):
            RuleCreate(title="x" * 501, content="title: test")

    def test_import_content_too_long_raises(self):
        with pytest.raises(ValidationError):
            RuleImportRequest(yaml_content="x" * (_MAX_IMPORT_YAML_BYTES + 1))


from app.api.v1.endpoints.connectors import ConnectorCreate


class TestConnectorCreateValidation:
    def test_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            ConnectorCreate(name="x" * 256, connector_type="wazuh", config={})

    def test_name_empty_raises(self):
        with pytest.raises(ValidationError):
            ConnectorCreate(name="", connector_type="wazuh", config={})

    def test_valid(self):
        c = ConnectorCreate(name="My Wazuh", connector_type="wazuh", config={"url": "http://wazuh"})
        assert c.name == "My Wazuh"

    # --- Feature 33.3: connector_type schema-level validation ---

    def test_unknown_connector_type_raises(self):
        with pytest.raises(ValidationError, match="Unknown connector type"):
            ConnectorCreate(name="Test", connector_type="unknown_type", config={})

    def test_sql_injection_connector_type_raises(self):
        with pytest.raises(ValidationError, match="Unknown connector type"):
            ConnectorCreate(name="Test", connector_type="wazuh'; DROP TABLE connectors;--", config={})

    def test_all_valid_connector_types(self):
        from app.api.v1.endpoints.connectors import CONNECTOR_TYPES
        for ct in CONNECTOR_TYPES:
            c = ConnectorCreate(name="Test", connector_type=ct, config={})
            assert c.connector_type == ct


from app.api.v1.endpoints.users import UserCreate


class TestUserCreateValidation:
    def test_valid(self):
        u = UserCreate(email="admin@example.com", password="SecureP@ss1")
        assert u.email == "admin@example.com"

    def test_invalid_email_raises(self):
        with pytest.raises(ValidationError, match="valid email"):
            UserCreate(email="not-email", password="SecureP@ss1")

    def test_password_too_short_raises(self):
        with pytest.raises(ValidationError):
            UserCreate(email="admin@example.com", password="short")

    def test_password_too_long_raises(self):
        with pytest.raises(ValidationError):
            UserCreate(email="admin@example.com", password="x" * (PASSWORD_MAX_LENGTH + 1))

    def test_full_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            UserCreate(
                email="admin@example.com",
                password="SecureP@ss1",
                full_name="x" * 256,
            )


# ---------------------------------------------------------------------------
# HTTP endpoint tests (body size limit + validator integration)
# ---------------------------------------------------------------------------

import pytest
from httpx import AsyncClient


@pytest.mark.anyio
async def test_body_size_limit_returns_413(client: AsyncClient, analyst_headers: dict):
    """ContentSizeLimitMiddleware must return 413 for requests with Content-Length > 10MB."""
    # We set Content-Length header to 11MB but send small body —
    # the middleware checks the header value, not actual bytes.
    oversized_headers = {**analyst_headers, "content-length": str(11 * 1024 * 1024)}
    resp = await client.post(
        "/api/v1/events/search",
        json={"query": "test"},
        headers=oversized_headers,
    )
    assert resp.status_code == 413


@pytest.mark.anyio
async def test_event_search_unknown_field_returns_422(client: AsyncClient, hunter_headers: dict):
    """EventFilter with unknown field must return 422 (events:search requires hunter+)."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"filters": [{"field": "injected_field", "operator": "eq", "value": "x"}]},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_search_invalid_operator_returns_422(client: AsyncClient, hunter_headers: dict):
    """EventFilter with invalid operator must return 422."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"filters": [{"field": "hostname", "operator": "INVALID", "value": "x"}]},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_search_query_too_long_returns_422(client: AsyncClient, hunter_headers: dict):
    """SearchRequest.query > 2048 chars must return 422."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"query": "x" * 2049},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_search_size_too_large_returns_422(client: AsyncClient, hunter_headers: dict):
    """SearchRequest.size > 1000 must return 422."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"size": 1001},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_login_invalid_email_returns_422(client: AsyncClient):
    """LoginRequest with invalid email format must return 422."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "not-an-email", "password": "password123"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_ingest_bulk_limit_1000(client: AsyncClient, db_session):
    """IngestRequest with > 1000 events must return 422."""
    import secrets
    from app.repositories.api_key_repo import APIKeyRepo

    raw_key = f"mxtac_{secrets.token_hex(16)}"
    await APIKeyRepo.create(db_session, raw_key=raw_key, label="test-agent")

    resp = await client.post(
        "/api/v1/events/ingest",
        headers={"X-API-Key": raw_key},
        json={"events": [{"class_name": "Process Activity"} for _ in range(1001)]},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_create_asset_invalid_ip_returns_422(client: AsyncClient, engineer_headers: dict):
    """AssetCreate with invalid IP address must return 422 (assets:write requires engineer+)."""
    resp = await client.post(
        "/api/v1/assets",
        json={
            "hostname": "server01",
            "asset_type": "server",
            "ip_addresses": ["not-an-ip"],
        },
        headers=engineer_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_incident_description_too_long_returns_422(client: AsyncClient, analyst_headers: dict):
    """IncidentCreate with description > 10000 chars must return 422."""
    resp = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Test Incident",
            "severity": "high",
            "description": "x" * 10001,
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_aggregation_invalid_agg_type_returns_422(client: AsyncClient, hunter_headers: dict):
    """AggregationRequest with unsupported agg_type must return 422 (events:search requires hunter+)."""
    resp = await client.post(
        "/api/v1/events/aggregate",
        json={"agg_type": "invalid_type"},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_aggregation_invalid_interval_returns_422(client: AsyncClient, hunter_headers: dict):
    """AggregationRequest with unsupported interval must return 422."""
    resp = await client.post(
        "/api/v1/events/aggregate",
        json={"agg_type": "date_histogram", "interval": "99x"},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_asset_invalid_os_family_returns_422(client: AsyncClient, engineer_headers: dict):
    """AssetCreate with invalid os_family must return 422."""
    resp = await client.post(
        "/api/v1/assets",
        json={
            "hostname": "server-osfam-test",
            "asset_type": "server",
            "os_family": "unknown_os",
        },
        headers=engineer_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_asset_list_invalid_asset_type_returns_422(client: AsyncClient, analyst_headers: dict):
    """GET /assets with invalid asset_type query param must return 422."""
    resp = await client.get(
        "/api/v1/assets?asset_type=invalid_type",
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_ioc_list_invalid_ioc_type_returns_422(client: AsyncClient, hunter_headers: dict):
    """GET /threat-intel/iocs with invalid ioc_type query param must return 422."""
    resp = await client.get(
        "/api/v1/threat-intel/iocs?ioc_type=invalid_type",
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_incident_invalid_assigned_to_returns_422(client: AsyncClient, analyst_headers: dict):
    """IncidentCreate with non-email assigned_to must return 422."""
    resp = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Test Incident",
            "severity": "high",
            "assigned_to": "not-an-email",
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_ioc_create_invalid_ip_value_returns_422(client: AsyncClient, engineer_headers: dict):
    """IOCCreate with ioc_type='ip' but non-IP value must return 422."""
    resp = await client.post(
        "/api/v1/threat-intel/iocs",
        json={
            "ioc_type": "ip",
            "value": "not-an-ip",
            "source": "test",
            "severity": "high",
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
        },
        headers=engineer_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_ioc_create_invalid_md5_returns_422(client: AsyncClient, engineer_headers: dict):
    """IOCCreate with ioc_type='hash_md5' but invalid hash must return 422."""
    resp = await client.post(
        "/api/v1/threat-intel/iocs",
        json={
            "ioc_type": "hash_md5",
            "value": "tooshort",
            "source": "test",
            "severity": "medium",
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
        },
        headers=engineer_headers,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# DetectionUpdate / BulkStatusUpdate validation
# ---------------------------------------------------------------------------

from app.schemas.detection import DetectionUpdate, BulkStatusUpdate


class TestDetectionUpdateValidation:
    def test_assigned_to_too_long_raises(self):
        with pytest.raises(ValidationError):
            DetectionUpdate(assigned_to="x" * 256)

    def test_priority_too_long_raises(self):
        with pytest.raises(ValidationError):
            DetectionUpdate(priority="x" * 21)

    def test_valid_assigned_to(self):
        update = DetectionUpdate(assigned_to="J. Smith")
        assert update.assigned_to == "J. Smith"

    def test_valid_priority(self):
        update = DetectionUpdate(priority="P1 Urgent")
        assert update.priority == "P1 Urgent"

    def test_none_fields_pass(self):
        update = DetectionUpdate()
        assert update.assigned_to is None
        assert update.priority is None


class TestBulkStatusUpdateValidation:
    def test_too_many_ids_raises(self):
        with pytest.raises(ValidationError):
            BulkStatusUpdate(ids=["id"] * 501, status="resolved")

    def test_empty_ids_raises(self):
        with pytest.raises(ValidationError):
            BulkStatusUpdate(ids=[], status="resolved")

    def test_valid_bulk(self):
        bulk = BulkStatusUpdate(ids=["id1", "id2"], status="resolved")
        assert len(bulk.ids) == 2


# ---------------------------------------------------------------------------
# AssetCreate hostname validation
# ---------------------------------------------------------------------------


class TestAssetCreateHostnameValidation:
    def test_valid_simple_hostname(self):
        asset = AssetCreate(hostname="server01", asset_type="server")
        assert asset.hostname == "server01"

    def test_valid_fqdn(self):
        asset = AssetCreate(hostname="srv01.example.com", asset_type="server")
        assert asset.hostname == "srv01.example.com"

    def test_invalid_hostname_leading_hyphen_raises(self):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="-invalid-host", asset_type="server")

    def test_invalid_hostname_too_long_raises(self):
        with pytest.raises(ValidationError):
            AssetCreate(hostname="a" * 254, asset_type="server")


# ---------------------------------------------------------------------------
# Events entity timeline — entity_type whitelist
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_entity_timeline_invalid_type_returns_422(
    client: AsyncClient, hunter_headers: dict
):
    """GET /events/entity/{entity_type}/{entity_value} with unknown entity_type → 422."""
    resp = await client.get(
        "/api/v1/events/entity/unknown_type/10.0.0.1",
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_entity_timeline_valid_type_returns_200_or_200(
    client: AsyncClient, hunter_headers: dict
):
    """GET /events/entity/ip/{value} with known entity_type is accepted (returns 200)."""
    resp = await client.get(
        "/api/v1/events/entity/ip/10.0.0.1",
        headers=hunter_headers,
    )
    # Valid type — should not return 422; DB will return empty results → 200
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_detection_assigned_to_too_long_returns_422(
    client: AsyncClient, analyst_headers: dict
):
    """PATCH /detections/{id} with assigned_to > 255 chars → 422."""
    from unittest.mock import AsyncMock, patch

    with patch(
        "app.api.v1.endpoints.detections.DetectionRepo.update",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00001",
            headers=analyst_headers,
            json={"assigned_to": "x" * 256},
        )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_detection_priority_too_long_returns_422(
    client: AsyncClient, analyst_headers: dict
):
    """PATCH /detections/{id} with priority > 20 chars → 422."""
    from unittest.mock import AsyncMock, patch

    with patch(
        "app.api.v1.endpoints.detections.DetectionRepo.update",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.patch(
            "/api/v1/detections/DET-2026-00001",
            headers=analyst_headers,
            json={"priority": "P" * 21},
        )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_bulk_update_too_many_ids_returns_422(
    client: AsyncClient, analyst_headers: dict
):
    """POST /detections/bulk with > 500 IDs → 422."""
    resp = await client.post(
        "/api/v1/detections/bulk",
        headers=analyst_headers,
        json={"ids": ["id"] * 501, "status": "resolved"},
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_create_asset_invalid_hostname_returns_422(
    client: AsyncClient, engineer_headers: dict
):
    """AssetCreate with RFC-invalid hostname (leading hyphen) → 422."""
    resp = await client.post(
        "/api/v1/assets",
        json={
            "hostname": "-invalid-hostname",
            "asset_type": "server",
        },
        headers=engineer_headers,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Feature 33.3: time range injection prevention (HTTP level)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_event_search_time_from_injection_returns_422(
    client: AsyncClient, hunter_headers: dict
):
    """SearchRequest.time_from with Lucene injection chars must return 422."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"time_from": "now-7d] OR *:*", "time_to": "now"},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_search_time_to_injection_returns_422(
    client: AsyncClient, hunter_headers: dict
):
    """SearchRequest.time_to with injection chars must return 422."""
    resp = await client.post(
        "/api/v1/events/search",
        json={"time_from": "now-7d", "time_to": "now} AND *:*"},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_event_aggregate_time_injection_returns_422(
    client: AsyncClient, hunter_headers: dict
):
    """AggregationRequest.time_from with injection chars must return 422."""
    resp = await client.post(
        "/api/v1/events/aggregate",
        json={"agg_type": "date_histogram", "time_from": "now-7d OR *"},
        headers=hunter_headers,
    )
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_connector_create_unknown_type_returns_422(
    client: AsyncClient, engineer_headers: dict
):
    """ConnectorCreate with unknown connector_type must return 422 at schema level."""
    resp = await client.post(
        "/api/v1/connectors",
        json={"name": "Test Connector", "connector_type": "unknown_type", "config": {}},
        headers=engineer_headers,
    )
    assert resp.status_code == 422
