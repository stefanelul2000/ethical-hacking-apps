"""
Live integration checks against a running MCP client deployment.

Run manually (not in CI) because it talks to the remote endpoint
and may hit rate limits or mutate production state.

Example:
  MCP_BASE_URL=https://ai-mcp-client.ciubi.net \
  MCP_ADMIN_USER=admin MCP_ADMIN_PASS=admin \
  python -m pytest tests/test_mcp_client_live.py
"""

from __future__ import annotations

import os
import time
import unittest
from typing import Dict, Optional

import requests

BASE_URL = os.getenv("MCP_BASE_URL", "https://dev-ai-mcp-client.ciubi.net")


def _auth_headers() -> Optional[Dict[str, str]]:
    user = os.getenv("MCP_ADMIN_USER")
    password = os.getenv("MCP_ADMIN_PASS")
    if not user or not password:
        return None
    auth = requests.auth.HTTPBasicAuth(user, password)
    return auth


class LiveMCPClientTests(unittest.TestCase):
    def test_health_endpoint(self):
        resp = requests.get(f"{BASE_URL}/health", timeout=10)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("ok", body)
        self.assertTrue(body["ok"])

    def test_servers_requires_auth(self):
        resp = requests.get(f"{BASE_URL}/servers", timeout=10)
        self.assertEqual(resp.status_code, 401)

    def test_servers_returns_data_when_authenticated(self):
        auth = _auth_headers()
        if not auth:
            self.skipTest("MCP_ADMIN_USER/PASS not provided")
        resp = requests.get(f"{BASE_URL}/servers", auth=auth, timeout=10)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("linked_servers", resp.json())

    def test_rate_limit_for_public_ask(self):
        if os.getenv("SKIP_RATE_LIMIT_TEST") == "1":
            self.skipTest("rate-limit test disabled")

        payload = {"question": "health-check"}
        # fire limit + 1 requests without auth to trigger 429
        status_codes = []
        for _ in range(6):
            resp = requests.post(
                f"{BASE_URL}/ask", json=payload, timeout=10
            )
            status_codes.append(resp.status_code)
            # tiny sleep to avoid clobbering network stack
            time.sleep(0.5)

        self.assertIn(429, status_codes)


if __name__ == "__main__":
    unittest.main()
