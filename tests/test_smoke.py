"""Smoke tests for the broker: no network, no Google calls (Secret Manager and the token exchange are mocked).

Run: python -m unittest discover -s tests
They pin what a dependency bump must not break: the routes answer, the OAuth URL carries exactly one PKCE challenge that
matches the broker's own verifier, the callback sends that verifier, and a bad state is refused.
"""
import base64
import hashlib
import os
import sys
import unittest
import urllib.parse

os.environ.update(PROJECT_ID="test-project", CLIENT_ID="cid.apps.googleusercontent.com",
                  REDIRECT_URI="https://broker.example/auth/callback", TOKEN_SERVICE_SECRET="s" * 32)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broker"))

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

main._get_client_secret = lambda *a, **k: "test-client-secret"


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class Smoke(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def auth_query(self):
        r = self.client.get("/auth", follow_redirects=False)
        self.assertEqual(r.status_code, 307)
        return urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual((r.status_code, r.json()), (200, {"status": "ok"}))

    def test_auth_url_has_one_challenge_matching_the_brokers_verifier(self):
        q = self.auth_query()
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual(q["access_type"], ["offline"])
        verifier = main._verify_state(q["state"][0])["cv"]
        self.assertEqual(q["code_challenge"], [challenge(verifier)])

    def test_callback_sends_the_brokers_verifier(self):
        import requests_oauthlib
        sent = {}
        orig = requests_oauthlib.OAuth2Session.fetch_token
        requests_oauthlib.OAuth2Session.fetch_token = lambda self, url, **kw: sent.update(kw) or {"access_token": "a", "token_type": "Bearer"}
        try:
            verifier = main._verify_state(self.auth_query()["state"][0])["cv"]
            flow = main._make_flow()
            flow.redirect_uri = main.REDIRECT_URI
            flow.fetch_token(code="x", code_verifier=verifier)
        finally:
            requests_oauthlib.OAuth2Session.fetch_token = orig
        self.assertEqual(sent.get("code_verifier"), verifier)

    def test_bad_state_is_refused(self):
        r = self.client.get("/auth/callback", params={"code": "x", "state": "unsigned"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
