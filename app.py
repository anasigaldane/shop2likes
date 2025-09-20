from flask import Flask, request, jsonify
import json
import asyncio
from datetime import datetime, timedelta
from like_pb2 import like
from uid_generator_pb2 import uid_generator
from like_count_pb2 import Info
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import aiohttp
import requests
import binascii
import os
from config import CONFIG
from cachetools import TTLCache
import threading
import time
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# === Configuration ===
AUTH_URL = "https://shop2likejwt.vercel.app/token"
CACHE_DURATION = timedelta(hours=7).seconds
TOKEN_REFRESH_THRESHOLD = timedelta(hours=6).seconds

SERVERS = {
    "ME": "https://clientbp.ggblueshark.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
}

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# === Token Cache ===
class TokenCache:
    def __init__(self):
        self.cache = TTLCache(maxsize=100, ttl=CACHE_DURATION)
        self.last_refresh = {}
        self.lock = threading.Lock()
        self.session = requests.Session()

    def get_tokens(self, server_key):
        with self.lock:
            now = time.time()
            refresh_needed = (
                server_key not in self.cache
                or server_key not in self.last_refresh
                or (now - self.last_refresh.get(server_key, 0)) > TOKEN_REFRESH_THRESHOLD
            )
            if refresh_needed:
                self._refresh_tokens(server_key)
                self.last_refresh[server_key] = now
            return self.cache.get(server_key, [])

    def _refresh_tokens(self, server_key):
        retry_delay = 1
        for _ in range(2):
            try:
                creds = load_credentials(server_key)
                tokens = []
                for user in creds:
                    try:
                        params = {"uid": user["uid"], "password": user["password"]}
                        response = self.session.get(AUTH_URL, params=params, timeout=5)
                        if response.status_code == 200:
                            data = response.json()
                            if isinstance(data, list) and len(data) > 0:
                                token = data[0].get("token")
                                if token:
                                    tokens.append(token)
                    except Exception as e:
                        app.logger.error(f"Error fetching token for {user['uid']}: {str(e)}")
                        continue
                if tokens:
                    self.cache[server_key] = tokens
                    app.logger.info(f"Refreshed tokens for {server_key}")
                else:
                    self.cache[server_key] = []
                    app.logger.warning(f"No valid tokens for {server_key}")
            except Exception as e:
                app.logger.error(f"Error refreshing tokens for {server_key}: {str(e)}")
                time.sleep(retry_delay)
                retry_delay *= 2

token_cache = TokenCache()

# === Helpers ===
def load_credentials(server_key):
    with open(CONFIG[server_key], "r") as f:
        return json.load(f)

def encrypt_aes(data: bytes) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode()

def create_uid_protobuf(uid: str):
    msg = uid_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def create_like_protobuf(uid: str, region: str):
    msg = like()
    msg.uid = int(uid)
    msg.region = region
    return msg.SerializeToString()

def encode_uid(uid: str) -> str:
    return encrypt_aes(create_uid_protobuf(uid))

def decode_info(data: bytes):
    try:
        info = Info()
        info.ParseFromString(data)
        return info
    except Exception:
        return None

def get_headers(token: str):
    return {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB48"
    }

def make_request(uid_enc: str, url: str, token: str):
    try:
        data = bytes.fromhex(uid_enc)
        headers = get_headers(token)
        response = requests.post(url, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200:
            return decode_info(response.content)
        return None
    except Exception:
        return None

async def send_like_requests(uid: str, region: str, tokens: list, url: str):
    encrypted = encrypt_aes(create_like_protobuf(uid, region))
    data = bytes.fromhex(encrypted)

    async def send(token):
        try:
            headers = get_headers(token)
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, headers=headers) as resp:
                    return await resp.text()
        except Exception:
            return None

    tasks = [send(token) for token in tokens]
    return await asyncio.gather(*tasks)

# === Routes ===
@app.route("/like", methods=["GET"])
def like_player():
    uid = request.args.get("uid")
    if not uid or not uid.isdigit():
        return jsonify({
            "error": "Invalid UID",
            "message": "UID parameter is required and must contain only digits",
            "timestamp": datetime.utcnow().isoformat(),
            "status": 400
        }), 400

    region = None
    player_info = None
    for current_region in SERVERS:
        tokens = token_cache.get_tokens(current_region)
        if not tokens:
            continue
        server_url = SERVERS[current_region]
        info_url = f"{server_url}/GetPlayerPersonalShow"
        player_info = make_request(encode_uid(uid), info_url, tokens[0])
        if player_info:
            region = current_region
            break

    if not player_info:
        return jsonify({
            "error": "Player not found",
            "message": "Player not found on any server",
            "status": 404
        }), 404

    before_likes = player_info.AccountInfo.Likes
    player_name = player_info.AccountInfo.PlayerNickname
    like_url = f"{SERVERS[region]}/LikeProfile"

    results = asyncio.run(send_like_requests(uid, region, token_cache.get_tokens(region), like_url))

    new_info = make_request(encode_uid(uid), info_url, token_cache.get_tokens(region)[0])
    after_likes = new_info.AccountInfo.Likes if new_info else before_likes

    return jsonify({
        "Credits": "https://t.me/nopethug",
        "player": player_name,
        "uid": uid,
        "likes_before": before_likes,
        "likes_after": after_likes,
        "likes_added": after_likes - before_likes,
        "server_region": region,
        "status": 1 if after_likes > before_likes else 2,
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.route("/health-check", methods=["GET"])
def health_check():
    try:
        for server in SERVERS:
            tokens = token_cache.get_tokens(server)
            if not tokens:
                return jsonify({
                    "status": "unhealthy",
                    "message": f"No tokens available for {server}",
                    "timestamp": datetime.utcnow().isoformat()
                }), 500
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)
