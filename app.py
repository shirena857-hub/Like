from flask import Flask, request, jsonify
import asyncio
import httpx
import aiohttp
import base64
import binascii
import json
import logging
import warnings
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson, ParseDict
from urllib3.exceptions import InsecureRequestWarning

# Protobuf imports
import like_pb2
import like_count_pb2
import uid_generator_pb2
import FreeFire_pb2

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# ========== CONSTANTS ==========
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB53"

# ========== HELPER FUNCTIONS ==========
def pad_data(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt_fast(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad_data(plaintext))

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt_fast(uid: str, password: str):
    try:
        account = f"uid={uid}&password={password}"
        token_val, open_id = await get_access_token(account)
        body = {
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        }
        login_req = FreeFire_pb2.LoginReq()
        ParseDict(body, login_req)
        proto_bytes = login_req.SerializeToString()
        payload = aes_cbc_encrypt_fast(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2022.3.47f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            res_msg = FreeFire_pb2.LoginRes.FromString(resp.content)
            return res_msg.token
    except Exception as e:
        app.logger.error(f"JWT Generation failed for {uid}: {e}")
        return None

async def load_tokens(server_name):
    """Asynchronously load tokens from accounts_{server_name}.json"""
    try:
        account_file = f"accounts_{server_name.lower()}.json"
        with open(account_file, "r") as f:
            accounts = json.load(f)
        tasks = [create_jwt_fast(str(acc['uid']), str(acc['password'])) for acc in accounts]
        jwt_list = await asyncio.gather(*tasks)
        tokens = [{"token": tk} for tk in jwt_list if tk]
        return tokens if tokens else None
    except Exception as e:
        app.logger.error(f"Token load failed for {server_name}: {e}")
        return None

# ========== FETCH PLAYER INFO FROM EXTERNAL API ==========
def fetch_player_info(uid):
    try:
        url = f"https://info-api-pearl.vercel.app/info?uid={uid}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            acc = data.get("AccountInfo", {})
            return {
                "Level": acc.get("AccountLevel", "NA"),
                "Region": acc.get("AccountRegion", "NA"),
                "ReleaseVersion": acc.get("ReleaseVersion", "NA")
            }
    except Exception as e:
        app.logger.error(f"Player info API error: {e}")
    return {"Level": "NA", "Region": "NA", "ReleaseVersion": "NA"}

# ========== ORIGINAL FUNCTIONS (encrypt, protobuf, requests) ==========
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption failed: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation (like) failed: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    return response.status
                return await response.text()
    except Exception as e:
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if not protobuf_message:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None

        tokens = await load_tokens(server_name)
        if not tokens:
            return None

        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"send_multiple_requests failed: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if not protobuf_data:
        return None
    return encrypt_message(protobuf_data)

def make_request(encrypt, server_name, token):
    try:
        # Choose correct URL based on region
        if server_name == "BD":
            url = "https://clientbp.ggwhitehawk.com/GetPlayerPersonalShow"
        elif server_name in {"IND", "US", "SAC", "NA"}:
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code != 200:
            app.logger.error(f"make_request HTTP {response.status_code}")
            return None
        binary = bytes.fromhex(response.content.hex())
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        app.logger.error(f"make_request failed: {e}")
        return None

# ========== FLASK ENDPOINT ==========
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        # 1. Fetch player info from external API
        player_info = fetch_player_info(uid)
        api_region = player_info["Region"]

        # 2. Resolve region: trust API only if it returns a real region (not "NA")
        if api_region != "NA" and api_region != server_name:
            app.logger.warning(f"Region mismatch: user gave {server_name}, API says {api_region}. Using API region.")
            final_region = api_region
        else:
            final_region = server_name

        # 3. Load tokens asynchronously (using a new event loop)
        tokens = asyncio.run(load_tokens(final_region))
        if not tokens:
            raise Exception("Failed to load tokens.")
        token = tokens[0]['token']

        # 4. Encrypt UID
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption of UID failed.")

        # 5. Get "before" likes
        before = make_request(encrypted_uid, final_region, token)
        if not before:
            raise Exception("Failed to retrieve initial player info.")
        before_json = json.loads(MessageToJson(before))
        before_like = int(before_json.get('AccountInfo', {}).get('Likes', 0))

        # 6. Choose LikeProfile URL
        if final_region == "BD":
            like_url = "https://clientbp.ggwhitehawk.com/LikeProfile"
        elif final_region == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif final_region in {"US", "NA", "BR", "SAC"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # 7. Send 100 likes (asynchronously)
        asyncio.run(send_multiple_requests(uid, final_region, like_url))

        # 8. Get "after" likes
        after = make_request(encrypted_uid, final_region, token)
        if not after:
            raise Exception("Failed to retrieve player info after like requests.")
        after_json = json.loads(MessageToJson(after))
        after_like = int(after_json.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(after_json.get('AccountInfo', {}).get('UID', 0))
        player_name = str(after_json.get('AccountInfo', {}).get('PlayerNickname', ''))

        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "Region": player_info["Region"],
            "Level": player_info["Level"],
            "UID": player_uid,
            "ReleaseVersion": player_info["ReleaseVersion"],
            "status": status
        }
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ========== RUN (for local development) ==========
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)