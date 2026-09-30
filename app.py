from flask import Flask, request, Response
import requests
import re
import logging
import time
import json
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote_plus

app = Flask(__name__)

BACKEND = "http://127.0.0.1:8080"

logging.basicConfig(
    filename='waf_blocks.log',
    level=logging.INFO,
    format='%(message)s'
)

RATE_LIMIT_WINDOW = 10   # seconds
RATE_LIMIT_MAX = 30      # max requests allowed per IP per window

request_log = defaultdict(list)


def is_rate_limited(ip):
    now = time.time()
    timestamps = request_log[ip]
    timestamps[:] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    timestamps.append(now)
    return len(timestamps) > RATE_LIMIT_MAX


RULES = {
    'SQLi': [
        r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
        r"union\s+select",
        r"select\s+.+\s+from",
        r"--\s",
        r";\s*drop\s+table"
    ],
    'XSS': [
        r"<script.*?>",
        r"javascript:",
        r"on\w+\s*="
    ],
    'PathTraversal': [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot\.ini"
    ]
}

COMPILED_RULES = {
    category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for category, patterns in RULES.items()
}


def inspect(path, query_string, body):
    combined = unquote_plus(f"{path} {query_string} {body}")
    for category, patterns in COMPILED_RULES.items():
        for pattern in patterns:
            match = pattern.search(combined)
            if match:
                return category, pattern.pattern, match.group()
    return None, None, None


def log_block(event):
    event['timestamp'] = datetime.utcnow().isoformat()
    logging.info(json.dumps(event))


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    client_ip = request.remote_addr

    if is_rate_limited(client_ip):
        log_block({
            'event': 'BLOCKED',
            'src_ip': client_ip,
            'rule': 'RateLimit',
            'reason': f'exceeded {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s',
            'path': f'/{path}'
        })
        return Response(
            "<h1>429 Too Many Requests</h1><p>Rate limit exceeded. Please slow down.</p>",
            429,
            {'Content-Type': 'text/html', 'Retry-After': str(RATE_LIMIT_WINDOW)}
        )

    query_string = request.query_string.decode('utf-8', errors='ignore')
    body = request.get_data(as_text=True) or ''

    category, pattern, matched_text = inspect(path, query_string, body)

    if category:
        log_block({
            'event': 'BLOCKED',
            'src_ip': client_ip,
            'rule': category,
            'pattern': pattern,
            'matched': matched_text,
            'path': f'/{path}',
            'query': query_string
        })
        return Response(
            f"<h1>403 Forbidden</h1><p>Request blocked by WAF: {category} pattern detected.</p>",
            403,
            {'Content-Type': 'text/html'}
        )

    url = f"{BACKEND}/{path}"

    resp = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        params=request.args,
        allow_redirects=False
    )

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded_headers]

    return Response(resp.content, resp.status_code, headers)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
