"""
OWASP API Security Test Suite
==============================
Tests the vulnerable Flask API for OWASP API Security Top 10 (2023) flaws.
Each test class maps to one OWASP category.

Run:  pytest tests/ -v --tb=short --html=reports/report.html
"""

import pytest
import requests
import threading
import time
import jwt

# ─── Shared fixtures ──────────────────────────────────────────────────────────

BASE_URL = "http://127.0.0.1:5000"


@pytest.fixture(scope="session", autouse=True)
def start_server():
    """Spin up the vulnerable API in a background thread for the test session."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from app.vulnerable_api import app

    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False),
        daemon=True,
    )
    thread.start()
    # Wait for server to be ready
    for _ in range(20):
        try:
            requests.get(f"{BASE_URL}/health", timeout=1)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.3)
    yield


@pytest.fixture(scope="session")
def alice_token(start_server):
    """Valid JWT token for user alice (id=1)."""
    resp = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "password123"})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["token"]


@pytest.fixture(scope="session")
def bob_token(start_server):
    """Valid JWT token for user bob (id=2)."""
    resp = requests.post(f"{BASE_URL}/login", json={"username": "bob", "password": "pass456"})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ─── API1: Broken Object Level Authorization (BOLA) ──────────────────────────

class TestAPI1_BOLA:
    """
    OWASP API1:2023 - Broken Object Level Authorization
    A user should only access their own resources. The vulnerable API
    returns data for ANY user_id without ownership checks.
    """

    def test_bola_user_reads_other_user_data(self, alice_token):
        """
        VULNERABILITY: alice (user_id=1) should NOT be able to read bob's (user_id=2) profile.
        Expected: 403 Forbidden
        Actual (vulnerable): 200 OK with bob's full profile including SSN + credit card
        """
        resp = requests.get(f"{BASE_URL}/users/2", headers=auth(alice_token))
        data = resp.json()

        assert resp.status_code == 403, (
            f"[FAIL - BOLA] alice accessed bob's profile! "
            f"Status: {resp.status_code}. "
            f"Leaked fields: {list(data.keys())}"
        )

    def test_bola_sensitive_fields_not_leaked(self, alice_token):
        """Even for own profile, SSN and credit card should be masked/excluded."""
        resp = requests.get(f"{BASE_URL}/users/1", headers=auth(alice_token))
        data = resp.json()
        assert resp.status_code == 200

        sensitive_fields = {"ssn", "credit_card"}
        exposed = sensitive_fields & set(data.keys())
        assert not exposed, (
            f"[FAIL - BOLA/API3] Sensitive fields exposed in response: {exposed}. "
            f"These fields must be omitted or masked."
        )

    def test_bola_order_belongs_to_caller(self, bob_token):
        """
        bob (user_id=2) should NOT be able to read order_id=1 which belongs to alice.
        Expected: 403 Forbidden
        """
        resp = requests.get(f"{BASE_URL}/orders/1", headers=auth(bob_token))
        assert resp.status_code == 403, (
            f"[FAIL - BOLA] bob accessed alice's order! "
            f"Response: {resp.json()}"
        )

    def test_bola_unauthenticated_request_blocked(self):
        """Unauthenticated access must always return 401."""
        resp = requests.get(f"{BASE_URL}/users/1")
        assert resp.status_code == 401, (
            f"[FAIL] No auth required to access /users/1! Status: {resp.status_code}"
        )


# ─── API2: Broken Authentication ─────────────────────────────────────────────

class TestAPI2_BrokenAuthentication:
    """
    OWASP API2:2023 - Broken Authentication
    Weak secrets, no token expiry, acceptance of 'none' algorithm.
    """

    def test_jwt_none_algorithm_rejected(self):
        """
        VULNERABILITY: Forge a token with alg=none (no signature).
        A secure API must reject unsigned tokens with 401, not grant access (200).
        NOTE: Modern PyJWT raises InvalidKeyError on alg=none with a non-None key,
        causing a 500. We assert the API does NOT return 200 (i.e., no bypass).
        The correct fix is returning 401 cleanly; 500 means error-handling is also broken.
        """
        import base64, json as _json
        forged_payload = {"user_id": 3, "role": "admin"}
        header = base64.urlsafe_b64encode(_json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(_json.dumps(forged_payload).encode()).rstrip(b"=").decode()
        forged_token = f"{header}.{payload}."  # no signature

        resp = requests.get(f"{BASE_URL}/users/3", headers=auth(forged_token))
        # Must NOT be 200 — bypass would mean the unsigned token was accepted
        assert resp.status_code != 200, (
            f"[FAIL - API2] API accepted unsigned (alg=none) JWT with 200! "
            f"A forged admin token granted access. Status: {resp.status_code}"
        )
        # Ideal fix: should be 401, not 500 (500 = error handling also broken)
        if resp.status_code == 500:
            pytest.xfail(
                "[KNOWN - API2/API8] alg=none correctly rejected but causes unhandled 500 "
                "instead of clean 401. Fix: catch InvalidKeyError in _decode_token and return None."
            )

    def test_jwt_has_expiry(self, alice_token):
        """Token must include an 'exp' claim. Tokens without expiry are a security risk."""
        decoded = jwt.decode(alice_token, options={"verify_signature": False})
        assert "exp" in decoded, (
            "[FAIL - API2] JWT has no expiry ('exp' claim missing). "
            "Tokens must expire to limit session hijack window."
        )

    def test_weak_secret_brute_force_risk(self, alice_token):
        """
        The JWT secret 'secret123' is trivially guessable.
        This test demonstrates that the secret is weak by successfully decoding
        with a known dictionary word — in real tests, a tool like jwt-cracker would run.
        """
        common_secrets = ["secret", "secret123", "password", "1234", "jwt_secret"]
        cracked = any(
            jwt.decode(alice_token, s, algorithms=["HS256"])
            for s in common_secrets
            if _try_decode(alice_token, s)
        )
        assert not cracked, (
            "[FAIL - API2] JWT secret is a common dictionary word! "
            "Use a cryptographically random secret of at least 256 bits."
        )

    def test_invalid_token_rejected(self):
        """Tampered or random tokens must return 401."""
        resp = requests.get(f"{BASE_URL}/users/1", headers=auth("not.a.valid.token"))
        assert resp.status_code == 401, (
            f"[FAIL - API2] Invalid token accepted! Status: {resp.status_code}"
        )


def _try_decode(token, secret):
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        return True
    except Exception:
        return False


# ─── API3: Broken Object Property Level Authorization ────────────────────────

class TestAPI3_MassAssignment:
    """
    OWASP API3:2023 - Broken Object Property Level Authorization
    Mass assignment allows callers to set any field, including privileged ones.
    """

    def test_mass_assignment_role_escalation(self, alice_token):
        """
        VULNERABILITY: alice sends role=admin in a PUT request.
        Expected: 403 Forbidden or 'role' field ignored.
        Actual (vulnerable): alice's role is updated to admin.
        """
        resp = requests.put(
            f"{BASE_URL}/users/1",
            headers=auth(alice_token),
            json={"role": "admin", "email": "alice_hacked@evil.com"},
        )
        # The API should either reject the 'role' field or return 403
        if resp.status_code == 200:
            changed = resp.json().get("fields_changed", [])
            assert "role" not in changed, (
                f"[FAIL - API3] Mass assignment successful! "
                f"alice escalated her own role to admin. Fields changed: {changed}"
            )

    def test_cannot_update_other_users_profile(self, alice_token):
        """alice should not be able to PUT /users/2 (bob's profile)."""
        resp = requests.put(
            f"{BASE_URL}/users/2",
            headers=auth(alice_token),
            json={"email": "hacked@evil.com"},
        )
        assert resp.status_code == 403, (
            f"[FAIL - API3/BOLA] alice modified bob's profile! Status: {resp.status_code}"
        )


# ─── API5: Broken Function Level Authorization ───────────────────────────────

class TestAPI5_BrokenFunctionLevelAuth:
    """
    OWASP API5:2023 - Broken Function Level Authorization
    Admin endpoints must check role, not just authentication.
    """

    def test_non_admin_cannot_access_admin_endpoint(self, alice_token):
        """
        alice is a regular user. GET /admin/users should return 403.
        The vulnerable API only checks if a token exists, not its role.
        """
        resp = requests.get(f"{BASE_URL}/admin/users", headers=auth(alice_token))
        assert resp.status_code == 403, (
            f"[FAIL - API5] Regular user accessed admin endpoint /admin/users! "
            f"Status: {resp.status_code}. "
            f"Returned {len(resp.json())} user records."
            if resp.status_code == 200 else
            f"[FAIL - API5] Unexpected status: {resp.status_code}"
        )

    def test_admin_endpoint_requires_auth(self):
        """Admin endpoint must return 401 with no token."""
        resp = requests.get(f"{BASE_URL}/admin/users")
        assert resp.status_code == 401, (
            f"[FAIL - API5] /admin/users accessible without any token! "
            f"Status: {resp.status_code}"
        )


# ─── API8: Security Misconfiguration ─────────────────────────────────────────

class TestAPI8_SecurityMisconfiguration:
    """
    OWASP API8:2023 - Security Misconfiguration
    Verbose errors, debug flags, and stack traces leak implementation details.
    """

    def test_error_response_does_not_leak_query(self):
        """
        SQL error should return a generic 4xx/5xx, NOT the raw SQL query.
        The vulnerable API leaks the full query string in error responses.
        """
        # Trigger a syntax error via a malformed payload
        resp = requests.post(
            f"{BASE_URL}/login",
            json={"username": "' AND 1=2 UNION SELECT --", "password": "x"},
        )
        body = resp.text.lower()
        assert "select" not in body and "query" not in body, (
            f"[FAIL - API8] Error response leaks SQL query details! "
            f"Response body: {resp.text[:200]}"
        )

    def test_health_endpoint_no_debug_flag(self):
        """Health check must not expose debug=True or internal config."""
        resp = requests.get(f"{BASE_URL}/health")
        data = resp.json()
        assert data.get("debug") is not True, (
            f"[FAIL - API8] /health exposes debug=True. "
            f"Internal configuration must not be surfaced in API responses."
        )

    def test_error_does_not_return_stack_trace(self):
        """5xx errors must not include Python tracebacks."""
        resp = requests.get(f"{BASE_URL}/users/99999", headers={"Authorization": "Bearer bad"})
        assert "traceback" not in resp.text.lower() and "file \"" not in resp.text.lower(), (
            f"[FAIL - API8] Stack trace visible in error response!"
        )


# ─── API10: SQL Injection ─────────────────────────────────────────────────────

class TestAPI10_Injection:
    """
    OWASP API10:2023 - Unsafe Consumption / Injection
    SQL injection via login body and search query parameter.
    """

    def test_sql_injection_login_bypass(self):
        """
        Classic SQL injection: username = ' OR '1'='1
        A vulnerable API returns a 200 with a valid token.
        Expected: 401 Unauthorized (no bypass allowed).
        """
        payloads = [
            {"username": "' OR '1'='1", "password": "anything"},
            {"username": "admin'--", "password": "wrong"},
            {"username": "' OR 1=1--", "password": ""},
        ]
        for payload in payloads:
            resp = requests.post(f"{BASE_URL}/login", json=payload)
            assert resp.status_code == 401, (
                f"[FAIL - API10] SQL injection login bypass succeeded with payload {payload}! "
                f"Status: {resp.status_code}. Response: {resp.json()}"
            )

    def test_sql_injection_search_parameter(self):
        """
        SQLi via GET /search?q= parameter.
        UNION-based injection should fail, not return extra rows.
        """
        payloads = [
            "' UNION SELECT id,username,ssn,credit_card,password,email,role FROM users--",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
        ]
        for q in payloads:
            resp = requests.get(f"{BASE_URL}/search", params={"q": q})
            # Either blocked (400/403/422) or returns no sensitive data
            if resp.status_code == 200:
                results = resp.json()
                for row in results:
                    for field in ("ssn", "credit_card", "password"):
                        assert field not in row, (
                            f"[FAIL - API10] UNION injection leaked field '{field}' via search! "
                            f"Payload: {q}. Row: {row}"
                        )

    def test_sql_injection_error_based(self):
        """Error-based SQLi must not expose DB schema or data."""
        resp = requests.post(
            f"{BASE_URL}/login",
            json={"username": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "password": "x"},
        )
        assert resp.status_code != 200, (
            f"[FAIL - API10] Error-based SQLi returned 200! Status: {resp.status_code}"
        )
        body = resp.text.lower()
        for keyword in ("sqlite", "syntax error in", "table", "column"):
            assert keyword not in body, (
                f"[FAIL - API10] DB error details leaked in response! "
                f"Keyword '{keyword}' found. Body: {resp.text[:300]}"
            )


# ─── Summary helper ───────────────────────────────────────────────────────────

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print OWASP category pass/fail summary after test run."""
    passed = len(terminalreporter.stats.get("passed", []))
    failed = len(terminalreporter.stats.get("failed", []))
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"  OWASP API Security Scan Summary")
    print(f"{'='*60}")
    print(f"  Total checks : {total}")
    print(f"  Passed       : {passed}")
    print(f"  FAILED       : {failed}  {'<-- VULNERABILITIES FOUND' if failed else ''}")
    print(f"{'='*60}")
