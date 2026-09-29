"""A stub of the Python package: each call is recorded as a tools/differential.sh
call row (LAST) and answered with a placeholder, so probe.py only mints."""
import base64, json, os

CALLS = open(os.environ['P7_CALLS'], 'w')
LAST = [None]


class Environment:
    PRODUCTION = 0
    SANDBOX = 1


class Config:
    def __init__(self, roots, clock):
        self.roots, self.clock = roots, clock

    @classmethod
    def create(cls, roots=None, clock=None):
        return cls(roots, clock)


class _Failure:
    class reason:
        name = 'STUB'


class _Result:
    verified = False
    failure = _Failure()


class Verifier:
    def __init__(self, config):
        self.config = config

    def _row(self, fn, text, env=None):
        roots = [base64.b64encode(r).decode() for r in (self.config.roots or [])]
        row = {'id': os.environ.get('P7_ID', '?'), 'fn': fn, 'config': json.dumps({'roots': roots}),
               'now': self.config.clock(), 'b64': base64.b64encode(text.encode()).decode()}
        if env is not None:
            row['env'] = env
        LAST[0] = row

    def verify_receipt(self, text):
        self._row('verify-receipt', text)
        return _Result()

    def verify_signed_data(self, text):
        self._row('verify-signed-data', text)
        return _Result()

    def verify_receipt_endpoint(self, env, body):
        self._row('verify-receipt-endpoint', body, env)
        return json.dumps({'status': -1})
