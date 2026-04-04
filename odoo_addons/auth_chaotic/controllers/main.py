import json
import hmac
import hashlib
import time
import os
import requests
import logging
from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)

# Shared secret used to verify that responses from FastAPI are authentic.
# Must match the CHAOTIC_SHARED_SECRET env var on the FastAPI server.
CHAOTIC_SHARED_SECRET = os.environ.get("CHAOTIC_SHARED_SECRET", "chaotic-dev-secret")
CHAOTIC_BACKEND_URL = os.environ.get("CHAOTIC_BACKEND_URL", "http://localhost:8088")


def _verify_hmac(payload: dict) -> bool:
    """Verify HMAC signature on the FastAPI response."""
    signature = payload.get("signature")
    if not signature:
        return False
    user_id = payload.get("user_id", "")
    timestamp = payload.get("timestamp", 0)
    # Reject tokens older than 30 seconds
    if abs(time.time() - int(timestamp)) > 30:
        _logger.warning("Chaotic: HMAC timestamp expired")
        return False
    expected = hmac.new(
        CHAOTIC_SHARED_SECRET.encode(),
        f"{user_id}:{timestamp}".encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


CHAOTIC_REACT_URL = os.environ.get("CHAOTIC_REACT_URL", "http://localhost:5173")


class ChaoticAuthController(http.Controller):

    @http.route('/chaotic/signup', type='http', auth="none", methods=['GET'])
    def chaotic_signup_redirect(self):
        """Redirects user to our React signup page with the ?odoo=true flag."""
        redirect_url = f"{CHAOTIC_REACT_URL}/?odoo=true"
        return request.redirect(redirect_url)

    @http.route('/web/login/chaotic_verify', type='json', auth="none", methods=['POST'], csrf=False)
    def chaotic_verify(self, **post):
        """
        Endpoint called by chaotic_login.js.
        Receives: { login, proof, attestation_quote, nonce, timestamp }
        """
        payload = request.jsonrequest
        login = payload.get('login')

        if not login:
            return {"success": False, "error": "Login field is required"}

        _logger.info("Chaotic verification request received for user: %s", login)

        try:
            # 1. Forward the proof to our FastAPI verification authority
            response = requests.post(
                f"{CHAOTIC_BACKEND_URL}/api/auth/verify",
                json=payload,
                timeout=15
            )
            result = response.json()

            if result.get("success"):
                # 2. Verify HMAC signature to ensure response is from our FastAPI
                if not _verify_hmac(result):
                    _logger.warning("Chaotic: HMAC verification failed for user %s", login)
                    return {"success": False, "error": "Backend signature verification failed"}

                # 3. Find the Odoo user
                user = request.env['res.users'].sudo().search(
                    [('login', '=', login)], limit=1
                )
                if not user:
                    return {"success": False, "error": "Odoo user not found. Please sign up first."}

                # 4. Directly set session — bypasses Odoo's password check
                request.session.uid = user.id
                request.session.login = login
                request.session.session_token = user._compute_session_token(
                    request.session.sid
                )

                _logger.info("User %s successfully authenticated via Chaotic ZKP", login)
                return {"success": True, "redirect": "/web"}
            else:
                error_msg = result.get("detail") or result.get("message") or "Verification failed"
                _logger.warning("Chaotic verification failed for %s: %s", login, error_msg)
                return {"success": False, "error": error_msg}

        except requests.exceptions.ConnectionError:
            _logger.error("Chaotic backend unreachable at %s", CHAOTIC_BACKEND_URL)
            return {"success": False, "error": "Hardware authentication server is offline. Please try again later."}
        except Exception as e:
            _logger.error("Error in Chaotic Auth: %s", str(e))
            return {"success": False, "error": str(e)}
