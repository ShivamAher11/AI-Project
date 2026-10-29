import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_analyses_progress"),
        CheckConstraint("format IN ('pe', 'elf')", name="ck_analyses_format"),
        CheckConstraint("bitness IS NULL OR bitness IN (32, 64)", name="ck_analyses_bitness"),
        CheckConstraint("status IN ('CREATED','VALIDATING','STATIC_ANALYSIS','RE_ANALYSIS','NORMALIZING','DETECTION','AI_ANALYSIS','REPORTING','COMPLETED','PARTIAL','FAILED','CANCELLED')", name="ck_analyses_status"),
        CheckConstraint("decomp_status IN ('OK','FAILED','TIMEOUT','NOT_RUN')", name="ck_analyses_decomp_status"),
        CheckConstraint("ai_status IN ('OK','DEGRADED','DISABLED','NOT_RUN','FAILED')", name="ck_analyses_ai_status"),
        Index("ix_analyses_sha256", "sha256"),
        Index("ix_analyses_scoring_version", "scoring_version"),
        Index("ix_analyses_heartbeat_at", "heartbeat_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String, nullable=False, default="CREATED")
    stage: Mapped[str] = mapped_column(String, nullable=False, default="CREATED")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    format: Mapped[str] = mapped_column(String, nullable=False)
    arch: Mapped[str] = mapped_column(String, nullable=False)
    bitness: Mapped[int | None] = mapped_column(Integer)
    endian: Mapped[str] = mapped_column(String(2), nullable=False, default="le")
    extension_mismatch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    strings_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    possible_packing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    entry_point: Mapped[str | None] = mapped_column(Text)
    toolchain: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    scoring_version: Mapped[str] = mapped_column(String, nullable=False, default="1.0")
    rule_set_version: Mapped[str] = mapped_column(String, nullable=False, default="1.0")
    schema_version: Mapped[str] = mapped_column(String, nullable=False, default="1.0")
    decomp_status: Mapped[str] = mapped_column(String, nullable=False, default="NOT_RUN")
    ai_status: Mapped[str] = mapped_column(String, nullable=False, default="NOT_RUN")
    error_code: Mapped[str | None] = mapped_column(String)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Section(Base):
    __tablename__ = "sections"
    __table_args__ = (Index("ix_sections_analysis_id", "analysis_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    vaddr: Mapped[str | None] = mapped_column(Text)
    vsize: Mapped[int] = mapped_column(BigInteger, nullable=False)
    raw_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    perms: Mapped[str] = mapped_column(Text, nullable=False)
    entropy: Mapped[float] = mapped_column(Float, nullable=False)


class ImportSymbol(Base):
    __tablename__ = "import_symbols"
    __table_args__ = (Index("ix_import_symbols_analysis_name", "analysis_id", "name"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    library: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    ordinal: Mapped[int | None] = mapped_column(Integer)
    address: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text)


class ExportSymbol(Base):
    __tablename__ = "export_symbols"
    __table_args__ = (Index("ix_export_symbols_analysis_name", "analysis_id", "name"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    address: Mapped[str | None] = mapped_column(Text)
    ordinal: Mapped[int | None] = mapped_column(Integer)


class StringRecord(Base):
    __tablename__ = "string_records"
    __table_args__ = (Index("ix_string_records_analysis_id", "analysis_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    offset: Mapped[str] = mapped_column(Text, nullable=False)
    encoding: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str | None] = mapped_column(Text)


class Function(Base):
    __tablename__ = "functions"
    __table_args__ = (Index("ix_functions_analysis_address", "analysis_id", "address"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str | None] = mapped_column(Text)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    decompiler_status: Mapped[str] = mapped_column(String, nullable=False)
    assembly_excerpt: Mapped[str | None] = mapped_column(Text)
    decompiled_excerpt: Mapped[str | None] = mapped_column(Text)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_size: Mapped[int | None] = mapped_column(BigInteger)
    ai_summary: Mapped[str | None] = mapped_column(Text)


class CallEdge(Base):
    __tablename__ = "call_edges"
    __table_args__ = (
        CheckConstraint("edge_type IN ('direct','indirect','import')", name="ck_call_edges_type"),
        Index("ix_call_edges_analysis_caller", "analysis_id", "caller_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    caller_id: Mapped[str] = mapped_column(ForeignKey("functions.id", ondelete="CASCADE"), nullable=False)
    callee_id: Mapped[str] = mapped_column(Text, nullable=False)
    edge_type: Mapped[str] = mapped_column(String, nullable=False)


class Signal(Base):
    __tablename__ = "signals"
    __table_args__ = (Index("ix_signals_analysis_rule", "analysis_id", "rule_id"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    function_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity IN ('low','medium','high','critical')", name="ck_findings_severity"),
        CheckConstraint("confidence IN ('low','medium','high')", name="ck_findings_confidence"),
        CheckConstraint("confidence_score >= 0 AND confidence_score <= 1", name="ck_findings_confidence_score"),
        Index("ix_findings_analysis_id", "analysis_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[str] = mapped_column(String, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    interpretation: Mapped[str | None] = mapped_column(Text)
    alternative: Mapped[str | None] = mapped_column(Text)
    score_contribution: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    group_id: Mapped[str | None] = mapped_column(Text)
    signal_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("source_type IN ('function','import','string','section','rule','metadata')", name="ck_evidence_source_type"),
        Index("ix_evidence_finding_id", "finding_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String, nullable=False)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    offset_or_address: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)


class AttackMapping(Base):
    __tablename__ = "attack_mappings"
    __table_args__ = (
        CheckConstraint("confidence IN ('low','medium','high')", name="ck_attack_mappings_confidence"),
        CheckConstraint("confidence_score >= 0 AND confidence_score <= 1", name="ck_attack_mappings_confidence_score"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    technique_id: Mapped[str] = mapped_column(Text, primary_key=True)
    technique_name: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)


class AIRun(Base):
    __tablename__ = "ai_runs"
    __table_args__ = (
        CheckConstraint("stage IN ('func','correlate','report')", name="ck_ai_runs_stage"),
        Index("ix_ai_runs_analysis_id", "analysis_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    stage: Mapped[str] = mapped_column(String, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_version: Mapped[str] = mapped_column(Text, nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    output_schema_version: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_usage: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    error_code: Mapped[str | None] = mapped_column(Text)
