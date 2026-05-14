from pydantic import BaseModel, Field, HttpUrl, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy import Column, String, DateTime, JSON, Enum as SAEnum, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import enum

class Base(DeclarativeBase):
    pass

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class SeverityLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    info = "info"

# Pydantic Models
class ScanStepResponse(BaseModel):
    tool: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "target_url": "https://example.com",
            "auth_session_id": None,
            "tools": ["whatweb", "katana", "httpx", "ffuf", "nuclei", "zap"],
            "exploit_enabled": False,
        }
    })
    target_url: HttpUrl
    auth_session_id: Optional[UUID] = None
    tools: List[str] = Field(default_factory=lambda: ["katana", "nuclei"], min_length=1)
    exploit_enabled: bool = False

class ScanResponse(BaseModel):
    id: UUID
    target_url: str
    status: str
    created_at: datetime
    updated_at: datetime
    config: Dict[str, Any]
    steps: List[ScanStepResponse]

class ScanResultResponse(BaseModel):
    id: UUID
    scan_id: UUID
    tool: str
    severity: str
    url: Optional[str] = None
    vulnerability_type: Optional[str] = None
    description: Optional[str] = None
    raw_output: Dict[str, Any] = {}
    created_at: datetime

# ORM Models
class ScanORM(Base):
    __tablename__ = "scans"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.pending)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    
    steps: Mapped[List["ScanStepORM"]] = relationship("ScanStepORM", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")
    results: Mapped[List["ScanResultORM"]] = relationship("ScanResultORM", back_populates="scan", lazy="selectin", cascade="all, delete-orphan")

class ScanStepORM(Base):
    __tablename__ = "scan_steps"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.pending)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    scan: Mapped["ScanORM"] = relationship("ScanORM", back_populates="steps")

class ScanResultORM(Base):
    __tablename__ = "scan_results"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(SAEnum(SeverityLevel), default=SeverityLevel.info)
    url: Mapped[str] = mapped_column(String(2048), nullable=True)
    vulnerability_type: Mapped[str] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(String(4096), nullable=True)
    raw_output: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    
    scan: Mapped["ScanORM"] = relationship("ScanORM", back_populates="results")