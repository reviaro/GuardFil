"""Constants and immutable limits for GuardFil T2a Stage B durable budget ledger.

These values embody the numeric cost contract specified in research/t2a/codex-issue.md.
They are strictly immutable and cannot be overridden by callers.
"""

# Global budget ceiling: $2.00 USD in integer microdollars
GLOBAL_CEILING_MICROS: int = 2_000_000

# MAXIMUM reservation per forwarded request: $1.10 USD in integer microdollars (the worst case for the
# largest supported input plus the output cap).  A caller may reserve
# less, sized to the counted request: any amount in [MIN_RESERVATION_MICROS, RESERVATION_AMOUNT_MICROS].
# A settlement that costs more than its reservation still halts the ledger, so an undersized
# reservation fails safe.  Entries written before the change all carry the maximum and stay valid.
RESERVATION_AMOUNT_MICROS: int = 1_100_000

# Maximum forwarded requests throughout the entire experiment
MAX_FORWARDED_REQUESTS: int = 256  # the $2 ceiling is the binding limit

# Maximum in-flight requests at any one time (strictly 1)
MAX_IN_FLIGHT_REQUESTS: int = 1

# Accounting rate: $1.00 USD per million tokens = 1 microUSD per token
# Applied to total input and output without cache discounts
INPUT_TOKEN_RATE_MICROS: int = 1
OUTPUT_TOKEN_RATE_MICROS: int = 1

# Supported token bounds
MAX_INPUT_TOKENS: int = 1_050_000
MAX_OUTPUT_TOKENS: int = 1024

# Smallest allowed reservation: what the output cap alone can cost.
MIN_RESERVATION_MICROS: int = MAX_OUTPUT_TOKENS * OUTPUT_TOKEN_RATE_MICROS

# Pinned model and service tier
PINNED_MODEL: str = "gpt-6-luna"
PINNED_SERVICE_TIER: str = "default"

# Per-model accounting (M3 step 7, model-neutral broker): model id as the
# provider reports it -> (input micro-USD per token, output micro-USD per token,
# service tier the receipt must carry).  The one $2 ceiling covers them all.
# Only models listed here can be settled.
MODEL_RATES: dict = {
    PINNED_MODEL: (INPUT_TOKEN_RATE_MICROS, OUTPUT_TOKEN_RATE_MICROS, PINNED_SERVICE_TIER),
    # Gemini 3.8 and 3.6 Flash, Standard paid tier (aistudio.google.com/docs/pricing, checked
    # 2026-11-05): $0.75 in / $3.75 out per million tokens (output includes thinking) through
    # 2026-12-31, then $1.50 / $7.50.  Counted at the 2027 price from now on, 2 / 8 micro-USD per
    # token, so the count never falls below what Google bills (raised 2026-11-05).
    # 3.5 Flash-Lite is $0.30 / $2.50 with no change announced, rounded up to 1 / 3.
    # Each is charged only to the separate Gemini ledger ($2 per provider).
    "gemini-3.8-flash": (2, 8, "default"),
    "gemini-3.6-flash": (2, 8, "default"),
    "gemini-3.5-flash-lite": (1, 3, "default"),
    # Claude Sonnet 5.5, standard tier (checked 2026-11-05 on platform.claude.com pricing):
    # $2 in / $10 out per million tokens = 2 / 10 micro-USD per token.  Separate Anthropic ledger.
    "claude-sonnet-5-5": (2, 10, "standard"),
}


def model_cost_micros(model: str, service_tier: str, input_tokens: int, output_tokens: int):
    """Accounted cost of one request, or None if the model or tier is not priced."""
    rates = MODEL_RATES.get(model)
    if rates is None or rates[2] != service_tier:
        return None
    return input_tokens * rates[0] + output_tokens * rates[1]

# Schema and file naming
DEFAULT_EXPERIMENT_ID: str = "guardfil-t2a-m1-openai-luna"
SCHEMA_VERSION: int = 1
STATE_FILENAME: str = "ledger.json"
LOCK_FILENAME: str = "ledger.lock"
LEASE_FILENAME: str = "lease.lock"
INTENT_FILENAME: str = "settlement_intent.json"
INTENT_FILE_PREFIX: str = "intent_"
CONFIRMATION_FILE_PREFIX: str = "confirmation_"
INSPECTION_GUARD_FILENAME: str = "inspection_guard.json"
INSPECTION_COMPLETION_FILENAME: str = "inspection_completion.json"
RECORD_TYPE_INSPECTION_GUARD: str = "INSPECTION_GUARD"
RECORD_TYPE_INSPECTION_COMPLETION: str = "INSPECTION_COMPLETION"
MAX_INSPECTION_GENERATION: int = 1_000_000_000  # Strict bound preventing counter wrap
MAX_STATE_FILE_BYTES: int = 524_288  # 512 KiB maximum state file size
MAX_IDENTIFIER_LENGTH: int = 128
MAX_DIGEST_LENGTH: int = 128
MAX_TIMESTAMP_LENGTH: int = 64
MAX_REASON_LENGTH: int = 256  # Maximum length of sanitized failure reason string
MAX_JOURNAL_ENTRIES: int = 514  # init + reserve/settle per request (2*256+2); was 258

# Closed receipt requirements
TERMINAL_STATUS_COMPLETED: str = "completed"

# Allowed bounded internal failure codes for terminal halt transitions
ALLOWED_INTERNAL_FAILURE_CODES = frozenset({
    "UNSETTLED_PENDING_RESERVATION_AT_STARTUP",
    "UNRESOLVED_SETTLEMENT_PUBLICATION",
    "PERMIT_MISMATCH",
    "INVALID_FAILURE_REASON_REJECTED",
    "INVALID_RECEIPT_EVIDENCE",
    "INVALID_EVIDENCE_TYPE",
    "INVALID_RECEIPT_STATUS",
    "RECEIPT_TOKEN_BOUND_EXCEEDED",
    "RECEIPT_MODEL_MISMATCH",
    "RECEIPT_SERVICE_TIER_MISMATCH",
    "REPLAYED_RESPONSE_ID",
    "SETTLEMENT_INTENT_WRITE_FAILED",
    "SETTLEMENT_CONFIRMATION_WRITE_FAILED",
    "SETTLEMENT_COMMITTED_CONFIRMATION_FAILED",
    "SETTLEMENT_WRITE_FAILED",
    "LEASE_VERIFICATION_FAILED_AT_SETTLE",
    "SYNC_IDENTITY_CHECK_FAILED",
    "HANDLE_CLOSED",
    "REQUEST_TRANSPORT_FAILURE",
    "UNFINISHED_INSPECTION_GUARD",
    "INSPECTION_COMPLETION_FAILED",
    "INSPECTION_GUARD_CORRUPT",
    "TERMINAL_UNCERTAINTY",
    "INSPECTION_EVIDENCE_UNCERTAINTY",
    "RECEIPT_SCHEMA_VIOLATION",
    "INVALID_RESPONSE_ID",
    "REQUEST_ID_MISMATCH",
    "REQUEST_DIGEST_MISMATCH",
    "INVALID_TOKEN_TYPE",
    "TOKEN_SUM_INCONSISTENT",
    "COST_EXCEEDS_RESERVATION",
    "RESERVE_DURABLE_WRITE_FAILED",
    "LEASE_VERIFICATION_FAILED_AT_RESERVE",
})

# Reasons a TERMINAL_UNCERTAINTY overlay event/halt may carry
TERMINAL_UNCERTAINTY_REASONS = frozenset({
    "TERMINAL_UNCERTAINTY",
    "UNRESOLVED_SETTLEMENT_PUBLICATION",
})

# Closed schema keys
EXPECTED_STATE_KEYS = frozenset({
    "schema_version",
    "experiment_id",
    "created_at_utc",
    "updated_at_utc",
    "global_ceiling_micros",
    "reservation_amount_micros",
    "committed_spend_micros",
    "retained_failed_micros",
    "total_reservations_count",
    "settled_requests_count",
    "pending_reservation",
    "halted",
    "halt_reason",
    "journal",
})

EXPECTED_PENDING_KEYS = frozenset({
    "reservation_id",
    "request_id",
    "request_digest",
    "reserved_amount_micros",
    "reserved_at_utc",
    "pid",
})

EXPECTED_RECEIPT_KEYS = frozenset({
    "status",
    "response_id",
    "request_id",
    "request_digest",
    "model",
    "service_tier",
    "input_tokens",
    "output_tokens",
    "total_tokens",
})

EXPECTED_INTENT_KEYS = frozenset({
    "record_type",
    "experiment_id",
    "reservation_id",
    "request_id",
    "request_digest",
    "response_id",
    "model",
    "service_tier",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "settled_amount_micros",
    "unencumbered_amount_micros",
    "timestamp_utc",
})

EXPECTED_CONFIRMATION_KEYS = frozenset({
    "record_type",
    "experiment_id",
    "reservation_id",
    "request_id",
    "request_digest",
    "response_id",
    "model",
    "service_tier",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "settled_amount_micros",
    "unencumbered_amount_micros",
    "timestamp_utc",
})

EXPECTED_INSPECTION_GUARD_KEYS = frozenset({
    "record_type",
    "experiment_id",
    "generation",
    "armed_at_utc",
})

EXPECTED_INSPECTION_COMPLETION_KEYS = frozenset({
    "record_type",
    "experiment_id",
    "generation",
    "completed_at_utc",
})

# Closed per-entry journal schemas
EXPECTED_JOURNAL_INITIALIZED_KEYS = frozenset({
    "entry_type",
    "experiment_id",
    "global_ceiling_micros",
    "timestamp_utc",
})

EXPECTED_JOURNAL_RESERVED_KEYS = frozenset({
    "entry_type",
    "reservation_id",
    "request_id",
    "request_digest",
    "reserved_amount_micros",
    "reservation_index",
    "timestamp_utc",
})

EXPECTED_JOURNAL_SETTLED_KEYS = frozenset({
    "entry_type",
    "reservation_id",
    "request_id",
    "request_digest",
    "response_id",
    "model",
    "service_tier",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "settled_amount_micros",
    "unencumbered_amount_micros",
    "timestamp_utc",
})

EXPECTED_JOURNAL_FAILED_RETAINED_KEYS = frozenset({
    "entry_type",
    "reservation_id",
    "request_id",
    "retained_amount_micros",
    "reason",
    "timestamp_utc",
})

EXPECTED_JOURNAL_ORPHANED_KEYS = frozenset({
    "entry_type",
    "reservation_id",
    "request_id",
    "retained_amount_micros",
    "reason",
    "timestamp_utc",
})

EXPECTED_JOURNAL_TERMINAL_UNCERTAINTY_KEYS = frozenset({
    "entry_type",
    "timestamp_utc",
    "reason",
    "uncertain_reservation_ids",
})

VALID_JOURNAL_ENTRY_TYPES = frozenset({
    "INITIALIZED",
    "RESERVED",
    "SETTLED",
    "FAILED_RETAINED",
    "ORPHANED_PENDING_HALTED",
    "TERMINAL_UNCERTAINTY",
})

# Strict type safety verification for monetary and numeric limits (reject bool and float)
assert type(GLOBAL_CEILING_MICROS) is int and not isinstance(GLOBAL_CEILING_MICROS, bool)
assert type(RESERVATION_AMOUNT_MICROS) is int and not isinstance(RESERVATION_AMOUNT_MICROS, bool)
assert type(INPUT_TOKEN_RATE_MICROS) is int and not isinstance(INPUT_TOKEN_RATE_MICROS, bool)
assert type(OUTPUT_TOKEN_RATE_MICROS) is int and not isinstance(OUTPUT_TOKEN_RATE_MICROS, bool)
assert type(MAX_FORWARDED_REQUESTS) is int and not isinstance(MAX_FORWARDED_REQUESTS, bool)
assert type(MAX_IN_FLIGHT_REQUESTS) is int and not isinstance(MAX_IN_FLIGHT_REQUESTS, bool)
assert type(MAX_INPUT_TOKENS) is int and not isinstance(MAX_INPUT_TOKENS, bool)
assert type(MAX_OUTPUT_TOKENS) is int and not isinstance(MAX_OUTPUT_TOKENS, bool)
assert type(SCHEMA_VERSION) is int and not isinstance(SCHEMA_VERSION, bool)
assert type(MAX_INSPECTION_GENERATION) is int and not isinstance(MAX_INSPECTION_GENERATION, bool)
assert type(MAX_STATE_FILE_BYTES) is int and not isinstance(MAX_STATE_FILE_BYTES, bool)
assert type(MAX_IDENTIFIER_LENGTH) is int and not isinstance(MAX_IDENTIFIER_LENGTH, bool)
assert type(MAX_DIGEST_LENGTH) is int and not isinstance(MAX_DIGEST_LENGTH, bool)
assert type(MAX_TIMESTAMP_LENGTH) is int and not isinstance(MAX_TIMESTAMP_LENGTH, bool)
assert type(MAX_REASON_LENGTH) is int and not isinstance(MAX_REASON_LENGTH, bool)
assert type(MAX_JOURNAL_ENTRIES) is int and not isinstance(MAX_JOURNAL_ENTRIES, bool)
