"""Lightweb gate for Fireseed.

Flow:
  1. Fetch a nonce from the site's `gate challenge` endpoint.
  2. Sign it with the member's Ed25519 private key.
  3. POST the signature to `gate verify`. Success returns a session token.
  4. On failure, run the site's `onfail` .js in a sandbox that can only
     clear the session and blank the view. Nothing else is exposed to it.

Needs: pip install cryptography quickjs
"""
import json
import os
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from quickjs import Context

KEY_PATH = os.path.expanduser("~/.fireseed/member_ed25519.pem")


def _load_key():
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _http(url, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = Request(url, data=body, headers={"Content-Type": "application/json",
                                           "User-Agent": "Fireseed/0.1"})
    with urlopen(req, timeout=8) as r:
        return r.read().decode("utf-8", "replace")


def authenticate(page_url, site):
    """Return a session token, or None if the gate refuses us."""
    try:
        nonce = json.loads(_http(urljoin(page_url, site["gate"]["challenge"])))["nonce"]
        sig = _load_key().sign(nonce.encode()).hex()
        reply = json.loads(_http(urljoin(page_url, site["gate"]["verify"]),
                                 {"nonce": nonce, "sig": sig}))
        return reply.get("token")
    except Exception:
        return None


def run_failure_script(js_text, state, log):
    """Run the site's onfail .js inside QuickJS with a tiny host API."""
    ctx = Context()
    ctx.set_time_limit(1)          # seconds
    ctx.set_memory_limit(8 * 1024 * 1024)

    def clear_session():
        state["token"] = None
        log("[runtime] session cleared")

    def blank_view():
        state["blank"] = True

    ctx.add_callable("host_clear_session", clear_session)
    ctx.add_callable("host_blank_view", blank_view)
    ctx.eval(js_text)


def enter(page_url, site, log):
    """Gate a site. Returns (allowed, token)."""
    state = {"token": None, "blank": False}
    token = authenticate(page_url, site)
    if token:
        return True, token
    if site.get("onfail"):
        try:
            js = _http(urljoin(page_url, site["onfail"]))
            run_failure_script(js, state, log)
        except Exception as e:
            log(f"[runtime] failure script error: {e}")
    log("Access denied. Nothing to show.")
    return False, None
