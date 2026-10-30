"""Request validation models."""
from typing import Literal

from pydantic import BaseModel, Field

from .core.config import settings

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(pattern=EMAIL_PATTERN, max_length=190)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(max_length=190)
    password: str = Field(max_length=128)


class ScanIn(BaseModel):
    code: str = Field(max_length=settings.MAX_CODE_CHARS)
    filename: str | None = Field(default=None, max_length=255)
    language: str | None = Field(default=None, max_length=30)
    run_code: bool = False


class ValidateIn(BaseModel):
    code: str = Field(max_length=settings.MAX_CODE_CHARS)
    filename: str | None = Field(default=None, max_length=255)
    language: str | None = Field(default=None, max_length=30)
    run_code: bool = True


class ApplyFixIn(BaseModel):
    finding_id: int | None = None
    apply_all: bool = False
    code: str | None = Field(default=None, max_length=settings.MAX_CODE_CHARS)


class RunIn(BaseModel):
    code: str = Field(max_length=settings.MAX_CODE_CHARS)
    language: str | None = Field(default=None, max_length=30)
    filename: str | None = Field(default=None, max_length=255)
    stdin: str = Field(default="", max_length=10_000)


class DetectIn(BaseModel):
    code: str = Field(default="", max_length=settings.MAX_CODE_CHARS)
    filename: str | None = Field(default=None, max_length=255)


class SettingsIn(BaseModel):
    theme: Literal["dark", "light"] = "dark"
    editor_font_size: int = Field(default=14, ge=11, le=24)
    auto_detect_language: bool = True
    default_report_format: Literal["pdf", "html", "json"] = "pdf"
    use_external_ai: bool = True
    run_code_on_validation: bool = True


DEFAULT_SETTINGS = SettingsIn().model_dump()
