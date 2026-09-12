import json
import base64
import gzip
import random
import sys

random.seed(1337)

BASE = "https://shop.example.com"
STATIC_HOST = "https://cdn.example.com"

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
]
LANGS = ["en-US,en;q=0.9", "vi-VN,vi;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9", "ja-JP,ja;q=0.9", "de-DE,de;q=0.8"]
CATEGORIES = ["electronics", "books", "clothing", "toys", "sports", "home-garden", "beauty", "automotive"]
BRANDS = ["acme", "globex", "initech", "umbrella", "stark-industries", "wayne-ent"]
SORT_OPTS = ["relevance", "price_asc", "price_desc", "newest", "rating"]
REFERERS = [f"{BASE}/", f"{BASE}/category/electronics", "https://www.google.com/", "https://www.facebook.com/", ""]
STATIC_EXTS = ["jpg", "png", "css", "js", "svg", "gif", "mp4"]


def entry(url, method="GET", cookies=None, headers=None, query=None,
          post_params=None, post_text=None, post_mime=None, status=200):
    hdrs = dict(headers or {})
    req = {
        "method": method, "url": url, "httpVersion": "HTTP/1.1",
        "cookies": [{"name": k, "value": v} for k, v in (cookies or {}).items()],
        "headers": [{"name": k, "value": v} for k, v in hdrs.items()],
        "queryString": [{"name": k, "value": v} for k, v in (query or {}).items()],
        "headersSize": -1, "bodySize": -1,
    }
    if post_params is not None or post_text is not None:
        post_data = {"mimeType": post_mime or "application/x-www-form-urlencoded"}
        if post_params is not None:
            post_data["params"] = [{"name": k, "value": v} for k, v in post_params.items()]
        if post_text is not None:
            post_data["text"] = post_text
        req["postData"] = post_data
    return {
        "startedDateTime": "2026-09-12T00:00:00.000Z",
        "time": random.randint(5, 300),
        "request": req,
        "response": {
            "status": status, "statusText": "OK" if status == 200 else "Error",
            "httpVersion": "HTTP/1.1", "cookies": [], "headers": [],
            "content": {"size": random.randint(100, 50000), "mimeType": "text/html"},
            "redirectURL": "", "headersSize": -1, "bodySize": -1,
        },
        "cache": {}, "timings": {"send": 0, "wait": random.randint(5, 300), "receive": 0},
    }


def gz_b64(raw: bytes) -> str:
    return base64.b64encode(gzip.compress(raw)).decode()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def realistic_jwt(seed: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": f"user{seed}", "iat": 1700000000 + seed, "exp": 1700003600 + seed}).encode()
    ).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(bytes([(seed * 31 + i) % 256 for i in range(32)])).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


def common_browser_headers(i):
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(LANGS),
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": random.choice(UAS),
        "Referer": random.choice(REFERERS),
        "Cache-Control": "no-cache" if i % 3 == 0 else "max-age=0",
        "Connection": "keep-alive",
        "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
    }


# ---------------------------------------------------------------------------
# 1. Realistic benign / noise traffic — the bulk of the file
# ---------------------------------------------------------------------------

noise_entries = []

N_STATIC = 120
for i in range(N_STATIC):
    ext = random.choice(STATIC_EXTS)
    noise_entries.append(entry(
        f"{STATIC_HOST}/assets/img/product-{i}.{ext}",
        headers={"Accept": "image/*", "User-Agent": random.choice(UAS), "Cache-Control": "max-age=31536000"},
    ))

N_BROWSE = 150
for i in range(N_BROWSE):
    noise_entries.append(entry(
        f"{BASE}/category/{random.choice(CATEGORIES)}",
        query={
            "page": str(i % 30 + 1),
            "sort": random.choice(SORT_OPTS),
            "brand": random.choice(BRANDS),
            "price_min": str(random.randint(0, 50) * 10),
            "price_max": str(random.randint(50, 200) * 10),
        },
        headers=common_browser_headers(i),
        cookies={"_ga": f"GA1.2.{random.randint(10**9,10**10)}.{1700000000+i}",
                 "cart_id": f"c{i:08d}", "locale": random.choice(["en", "vi", "fr"])},
    ))

N_SEARCH = 60
for i in range(N_SEARCH):
    noise_entries.append(entry(
        f"{BASE}/search",
        query={"q": f"product name {i}", "utm_source": "newsletter", "utm_medium": "email",
               "utm_campaign": f"promo{i % 12}", "fbclid": f"IwAR{i}xyz"},
        headers=common_browser_headers(i),
    ))

N_PRODUCT = 80
for i in range(N_PRODUCT):
    noise_entries.append(entry(
        f"{BASE}/api/products/{1000+i}",
        headers={**common_browser_headers(i), "Accept": "application/json"},
        cookies={"_ga": f"GA1.2.{random.randint(10**9,10**10)}.{1700000000+i}"},
    ))

N_TRACK = 70
for i in range(N_TRACK):
    noise_entries.append(entry(
        f"{BASE}/api/analytics/event", method="POST",
        post_text=json.dumps({"event": random.choice(["page_view", "add_to_cart", "click"]),
                               "session_id": f"s{i:08d}", "ts": 1700000000 + i, "page": f"/product/{i}"}),
        post_mime="application/json",
        headers={"Content-Type": "application/json", "User-Agent": random.choice(UAS)},
    ))

N_CART = 40
for i in range(N_CART):
    noise_entries.append(entry(
        f"{BASE}/api/cart/add", method="POST",
        post_params={"product_id": str(2000 + i), "qty": str(i % 5 + 1), "variant": random.choice(["S", "M", "L"])},
        cookies={"cart_id": f"c{i:08d}"},
    ))

N_AUTH_BENIGN = 25
for i in range(N_AUTH_BENIGN):
    noise_entries.append(entry(
        f"{BASE}/api/account/profile",
        headers={"Authorization": f"Bearer {realistic_jwt(i)}", "Accept": "application/json"},
    ))

N_XHR_MISC = 30
for i in range(N_XHR_MISC):
    noise_entries.append(entry(
        f"{BASE}/api/notifications",
        query={"since": str(1700000000 + i), "limit": "20"},
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    ))

N_WS = 10
for i in range(N_WS):
    noise_entries.append(entry(
        f"{BASE}/ws/live-updates",
        headers={
            "Upgrade": "websocket", "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(bytes(range(16))).decode(),
            "Sec-WebSocket-Version": "13",
        },
    ))

N_SPOOF = 15
for i in range(N_SPOOF):
    noise_entries.append(entry(
        f"{BASE}/api/whoami",
        headers={"X-Forwarded-For": f"10.0.{i % 255}.{(i * 7) % 255}", "X-Real-IP": f"192.168.{i % 255}.1"},
    ))

N_ERR = 20
for i in range(N_ERR):
    noise_entries.append(entry(f"{BASE}/api/products/{99000 + i}", status=random.choice([404, 500, 302]),
                                headers=common_browser_headers(i)))

print(f"Noise entries generated: {len(noise_entries)}", file=sys.stderr)

# ---------------------------------------------------------------------------
# 2. Malicious payloads — every known serialization format + every known
#    pipeline edge case, each embedded in a realistic-looking request.
# ---------------------------------------------------------------------------

php_priv_esc = 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}'
java_raw_short = b'\xac\xed\x00\x05sr\x00\x0bTestClass\x00'
java_raw_long = b'\xac\xed\x00\x05sr\x00\x11java.util.HashMap padding text to make this a realistically long serialized java object payload 1234567890'
ruby_raw_short = b'\x04\x08o:\x09Foo\x00'
ruby_raw_long = b'\x04\x08' + b'o:\x09Object\x00' + b'extra padding to make it a realistically long ruby marshal payload 1234567890'
dotnet_viewstate = "/wEPDwUJODk5MDMyNjU5D2QWAgIDD2QWAgIBD2QWAgIBDw8WAh4EVGV4dAUDMS4wZGQY"
nodejs_proto = b'{"__proto__":{"isAdmin":true},"padding":"1234567890123456789"}'
yaml_payload = b"!!python/object/apply:os.system ['id']"
pickle_payload = b"c__builtin__\neval\np0\n(S'1+1'\np1\ntp2\nRp3\n."

malicious_entries = [
    # --- PHP ---
    entry(f"{BASE}/my-account", cookies={"session": b64(php_priv_esc.encode())}),
    entry(f"{BASE}/my-account", headers={
        "Cookie": f"session={b64(php_priv_esc.encode())}; _ga=GA1.2.123.456; cart_id=c00000001"
    }),
    entry(f"{BASE}/my-account", headers={
        "Cookie": f"_ga=GA1.2.123.456; session={b64(php_priv_esc.encode())}; cart_id=c00000001"
    }),
    entry(f"{BASE}/my-account", headers={
        "Cookie": f"_ga=GA1.2.123.456; cart_id=c00000001; session={b64(php_priv_esc.encode())}"
    }),

    # --- Java ---
    entry(f"{BASE}/api/session", headers={"X-Session-Token": b64(java_raw_long)}),
    entry(f"{BASE}/api/session-gzip", headers={"X-Session-Token": gz_b64(java_raw_long)}),
    entry(f"{BASE}/api/session-short", headers={"X-Session-Token": b64(java_raw_short)}),
    entry(f"{BASE}/invoker/JMSInvokerServlet", method="POST",
          headers={"Content-Type": "application/x-java-serialized-object"},
          post_text=b64(java_raw_long), post_mime="application/x-java-serialized-object"),

    # --- .NET ---
    entry(f"{BASE}/Default.aspx", method="POST", post_params={
        "__VIEWSTATE": dotnet_viewstate,
        "__EVENTVALIDATION": "/wEWAwLXsY-DDA==",
    }),
    entry(f"{BASE}/api/state", headers={"X-View-State": gz_b64(dotnet_viewstate.encode())}),

    # --- NodeJS ---
    entry(f"{BASE}/api/update-profile", method="POST",
          post_text=json.dumps({"__proto__": {"isAdmin": True}}), post_mime="application/json"),
    entry(f"{BASE}/api/update-profile-hdr", headers={"X-Profile-Patch": gz_b64(nodejs_proto)}),

    # --- Ruby ---
    entry(f"{BASE}/dashboard", cookies={"rails_session": b64(ruby_raw_long)}),
    entry(f"{BASE}/dashboard-gzip", cookies={"rails_session": gz_b64(ruby_raw_long)}),
    entry(f"{BASE}/dashboard-short", cookies={"rails_session": b64(ruby_raw_short)}),

    # --- Wrapper ---
    entry(f"{BASE}/download", query={"file": "phar://uploads/avatar.jpg/test.txt"}),
    entry(f"{BASE}/download-gzip", query={"file": gz_b64(b'phar://uploads/avatar.jpg/test.txt padding here 12345')}),
    entry(f"{BASE}/proxy-fetch", query={"target": "gopher://internal-redis:6379/_INFO"}),

    # --- Pickle ---
    entry(f"{BASE}/api/task", query={"data": b64(pickle_payload)}),

    # --- YAML ---
    entry(f"{BASE}/api/config", method="POST", post_text=yaml_payload.decode(), post_mime="application/x-yaml"),
    entry(f"{BASE}/api/config-hdr", headers={"X-Config-Payload": gz_b64(yaml_payload)}),

    # --- Content-Disposition multipart edge case ---
    entry(f"{BASE}/api/upload-avatar", method="POST",
          headers={"Content-Disposition": f'form-data; name="avatar"; filename="{b64(php_priv_esc.encode())}.jpg"'},
          post_text="binary file placeholder", post_mime="multipart/form-data"),
]

random.shuffle(malicious_entries)

all_entries = noise_entries + malicious_entries
random.shuffle(all_entries)

har = {
    "log": {
        "version": "1.2",
        "creator": {"name": "EthicalQuoc comprehensive benchmark fixture", "version": "1.0"},
        "entries": all_entries,
    }
}

with open("TestCase/comprehensive.har", "w", encoding="utf-8") as f:
    json.dump(har, f, indent=2, ensure_ascii=False)

print(f"Wrote TestCase/comprehensive.har: {len(noise_entries)} noise + {len(malicious_entries)} malicious "
      f"= {len(all_entries)} total HTTP entries", file=sys.stderr)
