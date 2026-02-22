"""
Zeek log → OCSF normalizer.

Supports: conn.log, dns.log, http.log, ssl.log

Zeek conn.log TSV/JSON format:
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto,
  service, duration, orig_bytes, resp_bytes, conn_state, ...

Feature 7.8 — Zeek http.log → HTTPActivity (class_uid 4002):
  Extended HTTP fields captured in network_traffic:
    method, uri, status_code, status_msg, user_agent, referrer,
    resp_mime (resp_mime_types), request_body_len, response_body_len,
    trans_depth, version, orig_mime_types, username,
    orig_fuids, resp_fuids
  Endpoint ports captured from id.orig_p / id.resp_p.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .ocsf import (
    Endpoint, OCSFCategory, OCSFClass, OCSFEvent,
)

# Zeek conn_state → severity_id
CONN_STATE_SEVERITY: dict[str, int] = {
    "S0": 2,    # SYN sent, no reply — Low (potential scan)
    "REJ": 3,   # Connection rejected — Medium
    "RSTO": 2,  # Orig RST — Low
    "RSTR": 2,  # Resp RST — Low
    "OTH": 1,   # Other
}


class ZeekNormalizer:
    """Transforms a Zeek log dict (any log type) into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        log_type = raw.get("_log_type", "conn")

        if log_type == "conn":
            return self._normalize_conn(raw)
        if log_type == "dns":
            return self._normalize_dns(raw)
        if log_type == "http":
            return self._normalize_http(raw)
        if log_type == "ssl":
            return self._normalize_ssl(raw)

        # Fallback to generic network activity
        return self._normalize_conn(raw)

    def _normalize_conn(self, raw: dict[str, Any]) -> OCSFEvent:
        conn_state = raw.get("conn_state", "OTH")
        return OCSFEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            class_name="Network Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_ts(raw.get("ts")),
            severity_id=CONN_STATE_SEVERITY.get(conn_state, 1),
            metadata_product="Zeek",
            metadata_uid=raw.get("uid"),
            src_endpoint=Endpoint(
                ip=raw.get("id.orig_h"),
                port=self._safe_int(raw.get("id.orig_p")),
            ),
            dst_endpoint=Endpoint(
                ip=raw.get("id.resp_h"),
                port=self._safe_int(raw.get("id.resp_p")),
            ),
            network_traffic={
                "protocol":      raw.get("proto"),
                "service":       raw.get("service"),
                "duration":      raw.get("duration"),
                "orig_bytes":    raw.get("orig_bytes"),
                "resp_bytes":    raw.get("resp_bytes"),
                "conn_state":    conn_state,
                # Extended fields for comprehensive NetworkActivity coverage
                "missed_bytes":  raw.get("missed_bytes"),
                "history":       raw.get("history"),
                "orig_pkts":     raw.get("orig_pkts"),
                "resp_pkts":     raw.get("resp_pkts"),
                "orig_ip_bytes": raw.get("orig_ip_bytes"),
                "resp_ip_bytes": raw.get("resp_ip_bytes"),
                "local_orig":    raw.get("local_orig"),
                "local_resp":    raw.get("local_resp"),
                "tunnel_parents": raw.get("tunnel_parents", []),
                "vlan":          raw.get("vlan"),
            },
            raw=raw,
        )

    def _normalize_dns(self, raw: dict[str, Any]) -> OCSFEvent:
        return OCSFEvent(
            class_uid=OCSFClass.DNS_ACTIVITY,
            class_name="DNS Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_ts(raw.get("ts")),
            severity_id=1,
            metadata_product="Zeek",
            metadata_uid=raw.get("uid"),
            src_endpoint=Endpoint(ip=raw.get("id.orig_h")),
            dst_endpoint=Endpoint(ip=raw.get("id.resp_h")),
            network_traffic={
                "query":       raw.get("query"),
                "qtype":       raw.get("qtype_name"),
                "answers":     raw.get("answers", []),
                "rcode":       raw.get("rcode_name"),
                "proto":       raw.get("proto"),
            },
            raw=raw,
        )

    def _normalize_http(self, raw: dict[str, Any]) -> OCSFEvent:
        """Map Zeek http.log → OCSF HTTPActivity (class_uid 4002).

        Feature 7.8: Extended HTTP fields including body sizes, status text,
        pipeline depth, MIME types, auth username, and file UIDs.
        """
        return OCSFEvent(
            class_uid=OCSFClass.HTTP_ACTIVITY,
            class_name="HTTP Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_ts(raw.get("ts")),
            severity_id=1,
            metadata_product="Zeek",
            metadata_uid=raw.get("uid"),
            src_endpoint=Endpoint(
                ip=raw.get("id.orig_h"),
                port=self._safe_int(raw.get("id.orig_p")),
            ),
            dst_endpoint=Endpoint(
                ip=raw.get("id.resp_h"),
                port=self._safe_int(raw.get("id.resp_p")),
                hostname=raw.get("host"),
            ),
            network_traffic={
                "method":              raw.get("method"),
                "uri":                 raw.get("uri"),
                "version":             raw.get("version"),
                "status_code":         raw.get("status_code"),
                "status_msg":          raw.get("status_msg"),
                "user_agent":          raw.get("user_agent"),
                "referrer":            raw.get("referrer"),
                "request_body_len":    raw.get("request_body_len"),
                "response_body_len":   raw.get("response_body_len"),
                "trans_depth":         raw.get("trans_depth"),
                "orig_mime_types":     raw.get("orig_mime_types"),
                "resp_mime":           raw.get("resp_mime_types"),
                "username":            raw.get("username"),
                "orig_fuids":          raw.get("orig_fuids", []),
                "resp_fuids":          raw.get("resp_fuids", []),
            },
            raw=raw,
        )

    def _normalize_ssl(self, raw: dict[str, Any]) -> OCSFEvent:
        return OCSFEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            class_name="Network Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_ts(raw.get("ts")),
            severity_id=1,
            metadata_product="Zeek",
            metadata_uid=raw.get("uid"),
            src_endpoint=Endpoint(ip=raw.get("id.orig_h")),
            dst_endpoint=Endpoint(
                ip=raw.get("id.resp_h"),
                hostname=raw.get("server_name"),
            ),
            network_traffic={
                "version":     raw.get("version"),
                "cipher":      raw.get("cipher"),
                "server_name": raw.get("server_name"),
                "established": raw.get("established"),
                "cert_chain":  raw.get("cert_chain_fuids"),
            },
            raw=raw,
        )

    def _parse_ts(self, ts: Any) -> datetime:
        if ts is None:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    def _safe_int(self, val: Any) -> int | None:
        try:
            return int(val) if val is not None else None
        except (ValueError, TypeError):
            return None
