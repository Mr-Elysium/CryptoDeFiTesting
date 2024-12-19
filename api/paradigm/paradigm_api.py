import requests
import time
import signal
from values import *
import base64
import hmac
import json
from urllib.parse import urljoin

class ApiException(Exception):
    pass

class ParadigmClient:
    def __init__(self):
        self.access_key = ACCESS_KEY
        self.secret_key = SECRET_KEY
        self.api_url = API_URL
        self.shutdown = False

    def _signal_handler(self, signum, frame):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        self.shutdown = True

    # this helper method handles rate-limiting to pause for the next cycle.
    def _handle_rate_limit(self, response):
        if response.code == 429:
            wait_time = float(response.headers.get('Retry-After', response.json().get('wait', 1)))
            print(f"Rate limit exceeded. Waiting for {wait_time} seconds before retrying.")
            time.sleep(wait_time)
            return True
        return False

    # this helper method handles authorization failure.
    def _handle_auth_failure(self, response):
        if response.code == 401:
            print("Authentication failed. Please check you API Key.")
            self.shutdown = True
            return True
        return False

    def _sign_request(self, method: str, endpoint: str, params: dict = None):
        method = method.encode("utf-8")
        endpoint = endpoint.encode("utf-8")
        body = json.dumps(params).encode("utf-8") if params else b''

        signing_key = base64.b64decode(self.secret_key)
        timestamp = str(int(time.time() * 1000)).encode('utf-8')
        message = b'\n'.join([timestamp, method.upper(), endpoint, body])
        digest = hmac.digest(signing_key, message, 'sha256')
        signature = base64.b64encode(digest)

        return timestamp, signature

    # this helper method compiles possible API responses and handlers.
    def api_request(self, method: str, endpoint: str, params: dict = None):
        timestamp, signature = self._sign_request(method, endpoint, params)
        headers = {
            'Authorization': f'Bearer {self.access_key}',
            'Paradigm-API-Timestamp': timestamp,
            'Paradigm-API-Signature': signature,
        }
        url = urljoin(self.api_url, endpoint)

        while True:
            if method == 'GET':
                resp = requests.get(url, headers=headers)
            elif method == 'POST':
                headers['Accept'] = 'application/json'
                resp = requests.post(url, headers=headers, json=params)
            elif method == 'DELETE':
                resp = requests.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            if self._handle_auth_failure(resp):
                return None
            if self._handle_rate_limit(resp):
                continue
            if resp.ok:
                return resp.json()
            raise ApiException(f"API request failed: {resp.text}")
