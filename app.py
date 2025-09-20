from flask import Flask, request, jsonify
import json
import asyncio
from datetime import datetime
from like_pb2 import like
from uid_generator_pb2 import uid_generator
from like_count_pb2 import Info
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import requests
import binascii
import os

app = Flask(__name__)

# ================== CONFIG ==================
AUTH_URL = "https://shop2likejwt.vercel.app/token"

# ================== UTILITIES ==================
def encrypt_aes(data: bytes) -> str:
    """AES-CBC Encryption with PKCS7 padding"""
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
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
    except:
        return None

def get_headers(token: str):
    return {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzMwNDg3NzExOSwibmlja25hbWUiOiJTaG9wMmxpa2VzIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6IjhjMjk2MjY3M2FiMTQxNmI3MWM5MTcyMDQxODBmNGQ5IiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjQxNjcyMDIxNDAsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzU3ODkxNzYxLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IiIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTAiLCJleHAiOjE3NTgzOTk3ODl9.C-wZghl7KeSlLYw5yB1CE5uJSPZzlGw2MXXfWXX2OqI",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB48"
    }

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

async def send_like_requests(uid: str, region: str, token: str, url: str):
    """Send like requests asynchronously"""
    encrypted = encrypt_aes(create_like_protobuf(uid, region))
    data = bytes.fromhex(encrypted)

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=data, headers=get_headers(token)) as resp:
                return await resp.text()
        except:
            return None

def get_token_and_server(uid: str, password: str):
    """Fetch JWT token and server URL from API"""
    try:
        response = requests.get(AUTH_URL, params={"uid": uid, "password": password}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            token = data.get("Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzMwNDg3NzExOSwibmlja25hbWUiOiJTaG9wMmxpa2VzIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6IjhjMjk2MjY3M2FiMTQxNmI3MWM5MTcyMDQxODBmNGQ5IiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjQxNjcyMDIxNDAsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzU3ODkxNzYxLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IiIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTAiLCJleHAiOjE3NTgzOTk3ODl9.C-wZghl7KeSlLYw5yB1CE5uJSPZzlGw2MXXfWXX2OqI")
            server_url = data.get("https://clientbp.ggblueshark.com")
            return token, server_url
    except:
        return None, None

# ================== ROUTES ==================
@app.route("/like", methods=["GET"])
def like_player():
    uid = request.args.get("uid")
    password = request.args.get("password")

    # Validations
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

    # Fetch token & server from API
    token, server_url = get_token_and_server(uid, password)
    if not token or not server_url:
        return jsonify({
            "error": "Token fetch failed",
            "message": "Cannot get token or server from API",
            "timestamp": datetime.utcnow().isoformat(),
            "status": 503
        }), 503

    # Get player info
    info_url = f"{server_url}/GetPlayerPersonalShow"
    like_url = f"{server_url}/LikeProfile"
    player_info = make_request(encode_uid(uid), info_url, token)
    if not player_info:
        return jsonify({
            "error": "Player not found",
            "message": f"Player UID {uid} not found",
            "timestamp": datetime.utcnow().isoformat(),
            "status": 404
        }), 404

    before_likes = player_info.AccountInfo.Likes
    player_name = player_info.AccountInfo.PlayerNickname

    # Send like (async)
    asyncio.run(send_like_requests(uid, "ME", token, like_url))

    # Get updated likes
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
    }), 200

# ================== MAIN ==================
if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)
