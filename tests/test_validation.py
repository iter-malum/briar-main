import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from shared.models import ScanCreateRequest
from pydantic import ValidationError, HttpUrl

def test_valid_scan_request_default_tools():
    data = {"target_url": "https://target-app.com/login"}
    req = ScanCreateRequest(**data)
    assert str(req.target_url) == "https://target-app.com/login"
    assert req.tools == ["katana", "nuclei"]
    assert req.auth_session_id is None

def test_valid_scan_request_custom():
    data = {
        "target_url": "https://example.com",
        "auth_session_id": "550e8400-e29b-41d4-a716-446655440000",
        "tools": ["ffuf", "nuclei", "zap"]
    }
    req = ScanCreateRequest(**data)
    assert len(req.tools) == 3
    assert "zap" in req.tools

def test_invalid_url_format():
    with pytest.raises(ValidationError, match="Input should be a valid URL"):
        ScanCreateRequest(target_url="not-a-url", tools=[])

def test_empty_tools_list():
    with pytest.raises(ValidationError, match="List should have at least 1 item"):
        ScanCreateRequest(target_url="https://example.com", tools=[])

def test_invalid_auth_session_uuid():
    with pytest.raises(ValidationError):
        ScanCreateRequest(target_url="https://example.com", auth_session_id="invalid-uuid")