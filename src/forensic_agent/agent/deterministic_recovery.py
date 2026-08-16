"""Stable composition surface for bounded deterministic recovery.

Orchestration imports recovery primitives through this module. Concrete rule
implementations remain isolated by responsibility under
:mod:`forensic_agent.agent.recovery`.
"""

from __future__ import annotations

from forensic_agent.agent.recovery.carve_continuation import (
    _CARVED_FILE_DATA_TYPE,
    _CONTINUATION_METRICS_SCHEMA_ID,
    _CONTINUATION_SAFETY_CAP,
    _TEXT_BEARING_CARVE_TYPES,
    _carve_read_affordance,
    _empty_continuation_metrics,
    _follow_unique_content_continuation,
    _next_carve_read_continuation,
    _successful_carve_read_exists,
    _unconsumed_carve_read_candidates,
)
from forensic_agent.agent.recovery.common import (
    _case_bundle_sha256,
    _realized_continuation_arguments,
    _validated_continuation_result,
)
from forensic_agent.agent.recovery.cross_source_match import (
    _MATCH_WITH_CONTINUATION_METRICS_SCHEMA_ID,
    _empty_match_with_continuation_metrics,
    _follow_unique_match_with_continuation,
    _normalized_match_crc32,
    _positive_match_size,
    _trusted_match_with_candidates,
    _validate_match_with_target_result,
)
from forensic_agent.agent.recovery.memory_corroboration import (
    _MEMORY_INJECTION_CORROBORATION_METRICS_SCHEMA_ID,
    _empty_memory_injection_corroboration_metrics,
)
from forensic_agent.agent.recovery.memory_pagination import (
    _MEMORY_PAGINATION_METRICS_SCHEMA_ID,
    _MEMORY_PAGINATION_SAFETY_CAP,
    _empty_memory_pagination_metrics,
    _follow_memory_query_pagination,
    _memory_pagination_is_blocked,
    _memory_query_frontiers,
    _validated_memory_query_page,
)
from forensic_agent.agent.recovery.multisource_coverage import (
    _MULTISOURCE_COVERAGE_METRICS_SCHEMA_ID,
    _active_cross_source_disk_pcap,
    _direct_tool_modality,
    _empty_multisource_coverage_metrics,
    _receipt_covered_modalities,
    _specific_coverage_tool,
)
from forensic_agent.agent.recovery.pending_tool_recovery import (
    _PENDING_TOOL_RECOVERY_METRICS_SCHEMA_ID,
    _empty_pending_tool_recovery_metrics,
    _pending_final_tool_call,
    _PendingToolCall,
    _raw_tool_call_identity,
    _recover_pending_tool_call,
    _resolved_tool_messages,
)
from forensic_agent.agent.recovery.reference_evidence_recovery import (
    _REFERENCE_EVIDENCE_RECOVERY_METRICS_SCHEMA_ID,
    _empty_reference_evidence_recovery_metrics,
    _receipt_valid_case_result_count,
    _reference_evidence_tool_candidates,
    _reference_recovery_tool_candidates,
    _validated_reference_lookup_result,
)

__all__ = (
    "_CARVED_FILE_DATA_TYPE",
    "_CONTINUATION_METRICS_SCHEMA_ID",
    "_CONTINUATION_SAFETY_CAP",
    "_MATCH_WITH_CONTINUATION_METRICS_SCHEMA_ID",
    "_MEMORY_INJECTION_CORROBORATION_METRICS_SCHEMA_ID",
    "_MEMORY_PAGINATION_METRICS_SCHEMA_ID",
    "_MEMORY_PAGINATION_SAFETY_CAP",
    "_MULTISOURCE_COVERAGE_METRICS_SCHEMA_ID",
    "_PENDING_TOOL_RECOVERY_METRICS_SCHEMA_ID",
    "_REFERENCE_EVIDENCE_RECOVERY_METRICS_SCHEMA_ID",
    "_TEXT_BEARING_CARVE_TYPES",
    "_active_cross_source_disk_pcap",
    "_carve_read_affordance",
    "_case_bundle_sha256",
    "_direct_tool_modality",
    "_empty_continuation_metrics",
    "_empty_match_with_continuation_metrics",
    "_empty_memory_injection_corroboration_metrics",
    "_empty_memory_pagination_metrics",
    "_empty_multisource_coverage_metrics",
    "_empty_pending_tool_recovery_metrics",
    "_empty_reference_evidence_recovery_metrics",
    "_follow_memory_query_pagination",
    "_follow_unique_content_continuation",
    "_follow_unique_match_with_continuation",
    "_memory_pagination_is_blocked",
    "_memory_query_frontiers",
    "_next_carve_read_continuation",
    "_normalized_match_crc32",
    "_pending_final_tool_call",
    "_PendingToolCall",
    "_positive_match_size",
    "_raw_tool_call_identity",
    "_realized_continuation_arguments",
    "_receipt_covered_modalities",
    "_receipt_valid_case_result_count",
    "_recover_pending_tool_call",
    "_reference_evidence_tool_candidates",
    "_reference_recovery_tool_candidates",
    "_resolved_tool_messages",
    "_specific_coverage_tool",
    "_successful_carve_read_exists",
    "_trusted_match_with_candidates",
    "_unconsumed_carve_read_candidates",
    "_validate_match_with_target_result",
    "_validated_continuation_result",
    "_validated_memory_query_page",
    "_validated_reference_lookup_result",
)
