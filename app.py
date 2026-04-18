from flask import Flask, request, jsonify
import json, os, aiohttp, asyncio, requests, binascii
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import like_pb2, like_count_pb2, uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

ACCOUNTS_FILE = 'accounts.json'

# ✅ تحميل الحسابات
def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, 'r') as f:
            return json.load(f)
    return {}

# ✅ جلب التوكن من API
async def fetch_token(session, uid, password):
    url = f"https://jwt-mbv3.vercel.app/token?uid={uid}&password={password}"
    try:
        async with session.get(url, timeout=10) as res:
            if res.status == 200:
                text = await res.text()
                try:
                    data = json.loads(text)
                    if isinstance(data, list) and len(data) > 0 and "token" in data[0]:
                        return data[0]["token"]
                    elif isinstance(data, dict) and "token" in data:
                        return data["token"]
                except:
                    return None
    except:
        return None
    return None

# ✅ جلب كل التوكنات
async def get_tokens_live():
    accounts = load_accounts()
    tokens = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_token(session, uid, password) for uid, password in accounts.items()]
        results = await asyncio.gather(*tasks)
        tokens = [token for token in results if token]
    return tokens

# ✅ التشفير
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = uid_generator_pb2.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
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
    try:
        res = requests.post(url, data=bytes.fromhex(enc_uid), headers=headers, verify=False)
        return decode_protobuf(res.content)
    except:
        return None

# ✅ إصلاح: إضافة اسم للدالة - send_request
async def send_request(enc_uid, token):
    url = "https://clientbp.ggpolarbear.com/LikeProfile"
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
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(enc_uid), headers=headers, ssl=False) as r:
                return r.status
    except Exception as e:
        print(f"Error in send_request: {e}")
        return None

# ✅ إرسال لايكات لكل التوكنات
async def send_likes(uid, tokens):
    enc_uid = encrypt_message(create_like_proto(uid))
    tasks = [send_request(enc_uid, token) for token in tokens]
    return await asyncio.gather(*tasks)

# ✅ نقطة النهاية
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400
    try:
        # جلب التوكنات
        tokens = asyncio.run(get_tokens_live())
        if not tokens:
            return jsonify({"error": "No valid tokens available"}), 401

        # جلب البيانات قبل الإعجابات
        enc_uid = encrypt_message(create_uid_proto(uid))
        before = make_request(enc_uid, tokens[0])
        if not before:
            return jsonify({"error": "Failed to retrieve player info"}), 500

        before_data = json.loads(MessageToJson(before))
        likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
        nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")

        # إرسال الإعجابات
        responses = asyncio.run(send_likes(uid, tokens))
        success_count = sum(1 for r in responses if r == 200)

        # جلب البيانات بعد الإعجابات
        after = make_request(enc_uid, tokens[0])
        likes_after = likes_before  # القيمة الافتراضية إذا فشل الطلب
        if after:
            after_data = json.loads(MessageToJson(after))
            likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))

        return jsonify({
            "PlayerNickname": nickname,
            "UID": uid,
            "LikesBeforeCommand": likes_before,
            "LikesAfterCommand": likes_after,
            "LikesGivenByAPI": likes_after - likes_before,
            "SuccessfulRequests": success_count,
            "TotalRequests": len(tokens),
            "status": 1 if likes_after > likes_before else 2
        })

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/')
def home():
    return jsonify({"status": "online", "message": "Like API is running ✅"})

# ✅ هذا لا يُستخدم في Vercel ولكن نتركه للتشغيل المحلي
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
