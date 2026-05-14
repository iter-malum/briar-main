import pytest
import sys
import os
from unittest.mock import AsyncMock, patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

import pytest_asyncio
from fastapi.testclient import TestClient
from shared.models import ScanCreateRequest, ScanORM, ScanStepORM, ScanStatus

@pytest.fixture
def mock_session():
    mock = AsyncMock()
    mock.flush = AsyncMock()
    mock.commit = AsyncMock()
    mock.refresh = AsyncMock()
    return mock

@pytest.fixture
def mock_db_factory(mock_session):
    async def fake_get_db():
        yield mock_session
    return fake_get_db

def test_create_scan_logic():
    req = ScanCreateRequest(target_url="https://test.local", tools=["katana"])
    assert req.target_url == "https://test.local"
    assert req.tools == ["katana"]