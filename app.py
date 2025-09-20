from flask import Flask, request, jsonify
import json
import asyncio
from datetime import datetime, timedelta
from like_pb2 import like
from uid_generator_pb2 import uid_generator
from like_count_pb2 import Info
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import requests
import binascii
import os
import threading
import time

app = Flask(__name__)

# --- Configuration ---
AUTH_URL = "https://shop2likejwt.vercel.app/token"

SERVERS = {
    "ME": "https://clientbp.ggblueshark.com",
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.us.freefiremobile.com",
}

# --- AES Encrypt ---
def encrypt_aes(data: bytes) -> str:
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode()

# --- Protobuf generators ---
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
    except:
        return None

def get_headers(token: str):
    return {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"{token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB48"
    }

async def send_like_requests(uid: str, region: str, tokens: list, url: str):
    encrypted = encrypt_aes(create_like_protobuf(uid, region))
    data = bytes.fromhex(encrypted)

    async def send(token):
        try:
            headers = get_headers(token)
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, headers=headers) as resp:
                    return await resp.text()
        except:
            return None

    tasks = [send(token) for token in tokens]
    return await asyncio.gather(*tasks)

def make_request(uid_enc: str, url: str, token: str):
    data = bytes.fromhex(uid_enc)
    headers = get_headers(token)
    try:
        response = requests.post(url, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200:
            return decode_info(response.content)
        return None
    except:
        return None

# --- API token fetch ---
def get_token_and_server(uid: str, password: str):
    """Récupère token et server depuis l'API shop2likejwt"""
    try:
        response = requests.get(AUTH_URL, params={"uid": uid, "password": password}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            server_url = data.get("serverUrl") or SERVERS.get(data.get("lockRegion"))
            return token, server_url
    except Exception as e:
        app.logger.error(f"Error fetching token from API: {e}")
    return None, None

# --- Flask Routes ---
@app.route("/like", methods=["GET"])
def like_player():
    uid = request.args.get("uid")
    password = request.args.get("password")  # password من المستخدم

    if not uid or not password:
        return jsonify({
            "error": "Missing parameters",
            "message": "UID and password are required",
            "timestamp": datetime.utcnow().isoformat(),
            "status": 400
        }), 400
    
    if not uid.isdigit():
        return jsonify({
            "error": "Invalid UID",
            "message": "UID must contain only digits",
            "received_uid": uid,
            "timestamp": datetime.utcnow().isoformat(),
            "status": 400
        }), 400

    token, server_url = get_token_and_server(uid, password)
    if not token or not server_url:
        return jsonify({
            "error": "Token fetch failed",
            "message": "Unable to retrieve token or server URL from API",
            "status": 503,
            "timestamp": datetime.utcnow().isoformat()
        }), 503

    info_url = f"{server_url}/GetPlayerPersonalShow"
    like_url = f"{server_url}/LikeProfile"

    player_info = make_request(encode_uid(uid), info_url, token)
    if not player_info:
        return jsonify({
            "error": "Player not found",
            "message": f"Player UID {uid} not found on server",
            "status": 404,
            "timestamp": datetime.utcnow().isoformat()
        }), 404

    before_likes = player_info.AccountInfo.Likes
    player_name = player_info.AccountInfo.PlayerNickname

    # إرسال likes
    results = asyncio.run(send_like_requests(uid, "ME", [token], like_url))

    new_info = make_request(encode_uid(uid), info_url, token)
    after_likes = new_info.AccountInfo.Likes if new_info else before_likes

    return jsonify({
        "Credits": "https://t.me/nopethug",
        "player": player_name,
        "uid": uid,
        "likes_before": before_likes,
        "likes_after": after_likes,
        "likes_added": after_likes - before_likes,
        "server_url": server_url,
        "status": 1 if after_likes > before_likes else 2,
        "timestamp": datetime.utcnow().isoformat(),
    })

@app.route("/health-check", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)
