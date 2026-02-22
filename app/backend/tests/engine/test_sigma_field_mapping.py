"""Tests for feature 8.18 — Field mapping: OCSF event → flat Sigma dict.

Coverage for ``ocsf_to_sigma_flat()``:

  Common fields (always present):
  - _product is lowercase metadata_product
  - _category is class_uid as string

  OCSF dot-notation paths (always present):
  - process.cmd_line, process.name, process.path, process.pid
  - process.parent_name, process.parent_pid, process.hash_sha256
  - src_endpoint.ip, src_endpoint.hostname, src_endpoint.port, src_endpoint.domain
  - dst_endpoint.ip, dst_endpoint.hostname, dst_endpoint.port, dst_endpoint.domain
  - actor_user.name, actor_user.uid, actor_user.domain

  Backwards-compatible short names (process short names at top level):
  - name, cmd_line, pid, parent_name, parent_pid, hash_sha256
  - hostname, ip, port, domain (from src_endpoint)

  process_creation category aliases:
  - CommandLine maps from process.cmd_line
  - Image maps from process.path
  - OriginalFileName maps from process.name
  - ProcessId maps from process.pid
  - ParentImage maps from process.parent_name
  - ParentProcessId maps from process.parent_pid
  - User maps from actor_user.name
  - Hashes maps from process.hash_sha256

  network_connection category aliases:
  - SourceIp maps from src_endpoint.ip
  - SourcePort maps from src_endpoint.port
  - SourceHostname maps from src_endpoint.hostname
  - DestinationIp maps from dst_endpoint.ip
  - DestinationPort maps from dst_endpoint.port
  - DestinationHostname maps from dst_endpoint.hostname
  - Image maps from process.path
  - User maps from actor_user.name

  dns_query category aliases:
  - QueryName maps from network_traffic.query
  - QueryType maps from network_traffic.query_type
  - QueryResults maps from network_traffic.answers

  authentication category aliases:
  - TargetUserName maps from actor_user.name
  - TargetUserSid maps from actor_user.uid
  - TargetDomainName maps from actor_user.domain
  - IpAddress maps from src_endpoint.ip
  - WorkstationName maps from src_endpoint.hostname

  file_event category aliases:
  - TargetFilename maps from file.path
  - FileName maps from file.name
  - CommandLine maps from process.cmd_line
  - Image maps from process.path

  Null / missing value handling:
  - None OCSF values are NOT emitted as Sigma aliases
  - None values still present for dot-notation paths (None is valid)

  Unknown / missing logsource:
  - No Sigma aliases added for unknown category
  - None logsource → same as unknown category
  - Common and dot-notation keys are still present

  network_traffic and file pass-through:
  - network_traffic.* fields are flattened into result
  - file.* fields are flattened into result
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.engine.field_mapper import CATEGORY_MAPS, ocsf_to_sigma_flat
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
    UserInfo,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_event(**overrides: object) -> OCSFEvent:
    """Return a minimal OCSFEvent suitable for field-mapper tests."""
    kwargs: dict = dict(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="Wazuh",
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


def _proc(**kwargs: object) -> ProcessInfo:
    return ProcessInfo(**kwargs)  # type: ignore[arg-type]


def _endpoint(**kwargs: object) -> Endpoint:
    return Endpoint(**kwargs)  # type: ignore[arg-type]


def _user(**kwargs: object) -> UserInfo:
    return UserInfo(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Common fields — always present
# ---------------------------------------------------------------------------


def test_product_is_lowercased() -> None:
    event = _make_event(metadata_product="Wazuh")
    flat = ocsf_to_sigma_flat(event)
    assert flat["_product"] == "wazuh"


def test_product_already_lowercase_unchanged() -> None:
    event = _make_event(metadata_product="zeek")
    flat = ocsf_to_sigma_flat(event)
    assert flat["_product"] == "zeek"


def test_category_is_class_uid_string() -> None:
    event = _make_event(class_uid=OCSFClass.PROCESS_ACTIVITY)
    flat = ocsf_to_sigma_flat(event)
    assert flat["_category"] == str(OCSFClass.PROCESS_ACTIVITY)


def test_category_network_activity() -> None:
    event = _make_event(class_uid=OCSFClass.NETWORK_ACTIVITY)
    flat = ocsf_to_sigma_flat(event)
    assert flat["_category"] == "4001"


# ---------------------------------------------------------------------------
# OCSF dot-notation paths — always present
# ---------------------------------------------------------------------------


def test_dotpath_process_cmd_line() -> None:
    event = _make_event(process=_proc(cmd_line="powershell -enc abc"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.cmd_line"] == "powershell -enc abc"


def test_dotpath_process_name() -> None:
    event = _make_event(process=_proc(name="powershell.exe"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.name"] == "powershell.exe"


def test_dotpath_process_path() -> None:
    event = _make_event(process=_proc(path="C:\\Windows\\System32\\cmd.exe"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.path"] == "C:\\Windows\\System32\\cmd.exe"


def test_dotpath_process_pid() -> None:
    event = _make_event(process=_proc(pid=1234))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.pid"] == 1234


def test_dotpath_process_parent_name() -> None:
    event = _make_event(process=_proc(parent_name="explorer.exe"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.parent_name"] == "explorer.exe"


def test_dotpath_process_parent_pid() -> None:
    event = _make_event(process=_proc(parent_pid=999))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.parent_pid"] == 999


def test_dotpath_process_hash_sha256() -> None:
    sha = "a" * 64
    event = _make_event(process=_proc(hash_sha256=sha))
    flat = ocsf_to_sigma_flat(event)
    assert flat["process.hash_sha256"] == sha


def test_dotpath_src_ip() -> None:
    event = _make_event(src_endpoint=_endpoint(ip="192.168.1.10"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["src_endpoint.ip"] == "192.168.1.10"


def test_dotpath_src_hostname() -> None:
    event = _make_event(src_endpoint=_endpoint(hostname="client-01"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["src_endpoint.hostname"] == "client-01"


def test_dotpath_src_port() -> None:
    event = _make_event(src_endpoint=_endpoint(port=54321))
    flat = ocsf_to_sigma_flat(event)
    assert flat["src_endpoint.port"] == 54321


def test_dotpath_src_domain() -> None:
    event = _make_event(src_endpoint=_endpoint(domain="corp.example.com"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["src_endpoint.domain"] == "corp.example.com"


def test_dotpath_dst_ip() -> None:
    event = _make_event(dst_endpoint=_endpoint(ip="10.0.0.1"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["dst_endpoint.ip"] == "10.0.0.1"


def test_dotpath_dst_hostname() -> None:
    event = _make_event(dst_endpoint=_endpoint(hostname="dc-01"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["dst_endpoint.hostname"] == "dc-01"


def test_dotpath_dst_port() -> None:
    event = _make_event(dst_endpoint=_endpoint(port=443))
    flat = ocsf_to_sigma_flat(event)
    assert flat["dst_endpoint.port"] == 443


def test_dotpath_actor_user_name() -> None:
    event = _make_event(actor_user=_user(name="jdoe"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["actor_user.name"] == "jdoe"


def test_dotpath_actor_user_uid() -> None:
    event = _make_event(actor_user=_user(uid="S-1-5-21-000"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["actor_user.uid"] == "S-1-5-21-000"


def test_dotpath_actor_user_domain() -> None:
    event = _make_event(actor_user=_user(domain="CORP"))
    flat = ocsf_to_sigma_flat(event)
    assert flat["actor_user.domain"] == "CORP"


# ---------------------------------------------------------------------------
# Backwards-compatible short names
# ---------------------------------------------------------------------------


def test_shortname_name_from_process() -> None:
    event = _make_event(process=_proc(name="cmd.exe"))
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("name") == "cmd.exe"


def test_shortname_cmd_line_from_process() -> None:
    event = _make_event(process=_proc(cmd_line="cmd /c whoami"))
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("cmd_line") == "cmd /c whoami"


def test_shortname_pid_from_process() -> None:
    event = _make_event(process=_proc(pid=42))
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("pid") == 42


def test_shortname_hostname_from_src_endpoint() -> None:
    event = _make_event(src_endpoint=_endpoint(hostname="sensor-01"))
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("hostname") == "sensor-01"


def test_shortname_ip_from_src_endpoint() -> None:
    event = _make_event(src_endpoint=_endpoint(ip="172.16.0.5"))
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("ip") == "172.16.0.5"


# ---------------------------------------------------------------------------
# process_creation category aliases
# ---------------------------------------------------------------------------


_PC_LOGSOURCE = {"category": "process_creation", "product": "windows"}


def test_process_creation_command_line() -> None:
    event = _make_event(process=_proc(cmd_line="powershell -enc xxx"))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("CommandLine") == "powershell -enc xxx"


def test_process_creation_image_from_path() -> None:
    event = _make_event(process=_proc(path="C:\\Windows\\powershell.exe"))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("Image") == "C:\\Windows\\powershell.exe"


def test_process_creation_original_filename_from_name() -> None:
    event = _make_event(process=_proc(name="powershell.exe"))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("OriginalFileName") == "powershell.exe"


def test_process_creation_process_id() -> None:
    event = _make_event(process=_proc(pid=1337))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("ProcessId") == 1337


def test_process_creation_parent_image() -> None:
    event = _make_event(process=_proc(parent_name="explorer.exe"))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("ParentImage") == "explorer.exe"


def test_process_creation_parent_process_id() -> None:
    event = _make_event(process=_proc(parent_pid=4))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("ParentProcessId") == 4


def test_process_creation_user() -> None:
    event = _make_event(actor_user=_user(name="SYSTEM"))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("User") == "SYSTEM"


def test_process_creation_hashes() -> None:
    sha = "b" * 64
    event = _make_event(process=_proc(hash_sha256=sha))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert flat.get("Hashes") == sha


# ---------------------------------------------------------------------------
# network_connection category aliases
# ---------------------------------------------------------------------------


_NC_LOGSOURCE = {"category": "network_connection", "product": "zeek"}


def test_network_connection_source_ip() -> None:
    event = _make_event(src_endpoint=_endpoint(ip="10.1.2.3"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("SourceIp") == "10.1.2.3"


def test_network_connection_source_port() -> None:
    event = _make_event(src_endpoint=_endpoint(port=55000))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("SourcePort") == 55000


def test_network_connection_source_hostname() -> None:
    event = _make_event(src_endpoint=_endpoint(hostname="attacker.local"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("SourceHostname") == "attacker.local"


def test_network_connection_destination_ip() -> None:
    event = _make_event(dst_endpoint=_endpoint(ip="8.8.8.8"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("DestinationIp") == "8.8.8.8"


def test_network_connection_destination_port() -> None:
    event = _make_event(dst_endpoint=_endpoint(port=443))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("DestinationPort") == 443


def test_network_connection_destination_hostname() -> None:
    event = _make_event(dst_endpoint=_endpoint(hostname="c2.evil.com"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("DestinationHostname") == "c2.evil.com"


def test_network_connection_image_from_process_path() -> None:
    event = _make_event(process=_proc(path="C:\\Windows\\svchost.exe"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("Image") == "C:\\Windows\\svchost.exe"


def test_network_connection_user_from_actor() -> None:
    event = _make_event(actor_user=_user(name="jdoe"))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert flat.get("User") == "jdoe"


# ---------------------------------------------------------------------------
# dns_query category aliases
# ---------------------------------------------------------------------------


_DNS_LOGSOURCE = {"category": "dns_query", "product": "windows"}


def test_dns_query_name_from_network_traffic() -> None:
    event = _make_event(network_traffic={"query": "evil.example.com"})
    flat = ocsf_to_sigma_flat(event, _DNS_LOGSOURCE)
    assert flat.get("QueryName") == "evil.example.com"


def test_dns_query_type_from_network_traffic() -> None:
    event = _make_event(network_traffic={"query_type": "A"})
    flat = ocsf_to_sigma_flat(event, _DNS_LOGSOURCE)
    assert flat.get("QueryType") == "A"


def test_dns_query_results_from_network_traffic() -> None:
    event = _make_event(network_traffic={"answers": "1.2.3.4"})
    flat = ocsf_to_sigma_flat(event, _DNS_LOGSOURCE)
    assert flat.get("QueryResults") == "1.2.3.4"


def test_dns_query_image_from_process_path() -> None:
    event = _make_event(process=_proc(path="C:\\Windows\\dns.exe"))
    flat = ocsf_to_sigma_flat(event, _DNS_LOGSOURCE)
    assert flat.get("Image") == "C:\\Windows\\dns.exe"


# ---------------------------------------------------------------------------
# authentication category aliases
# ---------------------------------------------------------------------------


_AUTH_LOGSOURCE = {"category": "authentication", "product": "windows"}


def test_authentication_target_username() -> None:
    event = _make_event(actor_user=_user(name="Administrator"))
    flat = ocsf_to_sigma_flat(event, _AUTH_LOGSOURCE)
    assert flat.get("TargetUserName") == "Administrator"


def test_authentication_target_user_sid() -> None:
    event = _make_event(actor_user=_user(uid="S-1-5-21-500"))
    flat = ocsf_to_sigma_flat(event, _AUTH_LOGSOURCE)
    assert flat.get("TargetUserSid") == "S-1-5-21-500"


def test_authentication_target_domain_name() -> None:
    event = _make_event(actor_user=_user(domain="CORP"))
    flat = ocsf_to_sigma_flat(event, _AUTH_LOGSOURCE)
    assert flat.get("TargetDomainName") == "CORP"


def test_authentication_ip_address_from_src() -> None:
    event = _make_event(src_endpoint=_endpoint(ip="10.10.10.10"))
    flat = ocsf_to_sigma_flat(event, _AUTH_LOGSOURCE)
    assert flat.get("IpAddress") == "10.10.10.10"


def test_authentication_workstation_name_from_src() -> None:
    event = _make_event(src_endpoint=_endpoint(hostname="workstation-a"))
    flat = ocsf_to_sigma_flat(event, _AUTH_LOGSOURCE)
    assert flat.get("WorkstationName") == "workstation-a"


# ---------------------------------------------------------------------------
# file_event category aliases
# ---------------------------------------------------------------------------


_FE_LOGSOURCE = {"category": "file_event", "product": "windows"}


def test_file_event_target_filename_from_file_path() -> None:
    event = _make_event(file={"path": "C:\\Temp\\malware.exe"})
    flat = ocsf_to_sigma_flat(event, _FE_LOGSOURCE)
    assert flat.get("TargetFilename") == "C:\\Temp\\malware.exe"


def test_file_event_filename_from_file_name() -> None:
    event = _make_event(file={"name": "payload.dll"})
    flat = ocsf_to_sigma_flat(event, _FE_LOGSOURCE)
    assert flat.get("FileName") == "payload.dll"


def test_file_event_command_line_from_process() -> None:
    event = _make_event(process=_proc(cmd_line="dropper.exe /silent"))
    flat = ocsf_to_sigma_flat(event, _FE_LOGSOURCE)
    assert flat.get("CommandLine") == "dropper.exe /silent"


def test_file_event_image_from_process_path() -> None:
    event = _make_event(process=_proc(path="C:\\dropper.exe"))
    flat = ocsf_to_sigma_flat(event, _FE_LOGSOURCE)
    assert flat.get("Image") == "C:\\dropper.exe"


# ---------------------------------------------------------------------------
# file_change and file_delete use same map as file_event
# ---------------------------------------------------------------------------


def test_file_change_shares_map_with_file_event() -> None:
    event = _make_event(file={"path": "C:\\secret.txt"})
    for cat in ("file_change", "file_delete", "file_access"):
        flat = ocsf_to_sigma_flat(event, {"category": cat})
        assert flat.get("TargetFilename") == "C:\\secret.txt", f"failed for category={cat}"


# ---------------------------------------------------------------------------
# Null / missing value handling
# ---------------------------------------------------------------------------


def test_none_process_path_does_not_emit_image_alias() -> None:
    """process.path is None → Image alias is NOT added to the flat dict."""
    event = _make_event(process=_proc(path=None))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert "Image" not in flat


def test_none_actor_user_name_does_not_emit_user_alias() -> None:
    event = _make_event(actor_user=_user(name=None))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert "User" not in flat


def test_none_dst_ip_does_not_emit_destination_ip_alias() -> None:
    event = _make_event(dst_endpoint=_endpoint(ip=None))
    flat = ocsf_to_sigma_flat(event, _NC_LOGSOURCE)
    assert "DestinationIp" not in flat


def test_none_values_still_present_in_dot_paths() -> None:
    """None values are still present at dot-notation paths (not filtered)."""
    event = _make_event(process=_proc(cmd_line=None))
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert "process.cmd_line" in flat
    assert flat["process.cmd_line"] is None


# ---------------------------------------------------------------------------
# Unknown / missing logsource
# ---------------------------------------------------------------------------


def test_no_logsource_emits_no_sigma_aliases() -> None:
    """Calling with logsource=None produces no Sigma alias keys."""
    event = _make_event(
        process=_proc(cmd_line="evil.exe", path="C:\\evil.exe", name="evil.exe"),
        actor_user=_user(name="admin"),
    )
    flat = ocsf_to_sigma_flat(event, None)
    sigma_aliases = {"CommandLine", "Image", "OriginalFileName", "User", "Hashes",
                     "DestinationIp", "TargetUserName", "QueryName"}
    for alias in sigma_aliases:
        assert alias not in flat, f"Unexpected Sigma alias: {alias}"


def test_unknown_category_emits_no_sigma_aliases() -> None:
    event = _make_event(process=_proc(cmd_line="something"))
    flat = ocsf_to_sigma_flat(event, {"category": "nonexistent_category"})
    assert "CommandLine" not in flat
    assert "DestinationIp" not in flat


def test_unknown_category_common_fields_still_present() -> None:
    event = _make_event(metadata_product="SomeTool")
    flat = ocsf_to_sigma_flat(event, {"category": "nonexistent_category"})
    assert flat["_product"] == "sometool"
    assert "_category" in flat


def test_none_logsource_common_fields_still_present() -> None:
    event = _make_event(metadata_product="Wazuh")
    flat = ocsf_to_sigma_flat(event, None)
    assert flat["_product"] == "wazuh"
    assert "process.cmd_line" in flat
    assert "src_endpoint.ip" in flat


# ---------------------------------------------------------------------------
# network_traffic and file pass-through
# ---------------------------------------------------------------------------


def test_network_traffic_fields_are_flattened() -> None:
    event = _make_event(network_traffic={"proto": "tcp", "bytes_in": 1024})
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("network_traffic.proto") == "tcp"
    assert flat.get("network_traffic.bytes_in") == 1024


def test_file_fields_are_flattened() -> None:
    event = _make_event(file={"path": "/tmp/x", "size": 512})
    flat = ocsf_to_sigma_flat(event)
    assert flat.get("file.path") == "/tmp/x"
    assert flat.get("file.size") == 512


# ---------------------------------------------------------------------------
# Return type and shape
# ---------------------------------------------------------------------------


def test_result_is_dict() -> None:
    event = _make_event()
    assert isinstance(ocsf_to_sigma_flat(event), dict)


def test_result_is_non_empty() -> None:
    event = _make_event()
    assert len(ocsf_to_sigma_flat(event)) > 0


def test_all_keys_are_strings() -> None:
    event = _make_event(
        process=_proc(name="cmd.exe", cmd_line="cmd /c dir"),
        src_endpoint=_endpoint(ip="1.2.3.4"),
    )
    flat = ocsf_to_sigma_flat(event, _PC_LOGSOURCE)
    assert all(isinstance(k, str) for k in flat)


# ---------------------------------------------------------------------------
# CATEGORY_MAPS export
# ---------------------------------------------------------------------------


def test_category_maps_contains_process_creation() -> None:
    assert "process_creation" in CATEGORY_MAPS


def test_category_maps_contains_network_connection() -> None:
    assert "network_connection" in CATEGORY_MAPS


def test_category_maps_contains_dns_query() -> None:
    assert "dns_query" in CATEGORY_MAPS


def test_category_maps_contains_authentication() -> None:
    assert "authentication" in CATEGORY_MAPS


def test_category_maps_contains_file_categories() -> None:
    for cat in ("file_access", "file_change", "file_delete", "file_event"):
        assert cat in CATEGORY_MAPS, f"Missing category: {cat}"
