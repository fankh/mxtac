"""Schemas for ATT&CK-guided hunting suggestions (Feature 11.8)."""

from pydantic import BaseModel


class SuggestedQuery(BaseModel):
    """A pre-built hunt query that targets a specific technique or tactic.

    label     — human-readable name shown in the UI
    query     — free-text search string (Lucene-compatible)
    time_from — relative time range (e.g. "now-24h", "now-7d")
    """

    label: str
    query: str
    time_from: str


class HuntSuggestion(BaseModel):
    """A single ATT&CK-guided hunt suggestion derived from detection telemetry.

    technique_id      — ATT&CK technique ID (e.g. "T1003.006")
    technique_name    — human-readable name (e.g. "DCSync")
    tactic            — parent tactic name (e.g. "Credential Access")
    tactic_id         — ATT&CK tactic ID (e.g. "TA0006")
    reason            — one-line explanation of why this technique was surfaced
    priority          — "high" | "medium" | "low" — analyst urgency hint
    detection_count   — number of detections in the analysis window
    rule_count        — enabled Sigma rules covering this technique
    suggested_queries — ready-to-run hunt queries for this technique
    """

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    reason: str
    priority: str
    detection_count: int
    rule_count: int
    suggested_queries: list[SuggestedQuery]


class HuntSuggestionsResponse(BaseModel):
    """Response envelope for GET /hunting/suggestions.

    suggestions   — ranked list of hunt suggestions (highest priority first)
    generated_at  — ISO-8601 UTC timestamp when the suggestions were computed
    window_hours  — the detection analysis window used (default 24)
    """

    suggestions: list[HuntSuggestion]
    generated_at: str
    window_hours: int
