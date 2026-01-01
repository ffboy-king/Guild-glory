import threading
import jwt
import random
from threading import Thread
import json
import requests 
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from flask import Flask  # KOYEB FIX ADDED

# --- TRY IMPORTING USER FILES ---
try:
    from important_zitado import *
    from byte import *
except ImportError:
    pass

# ==========================================
#  KOYEB KEEP ALIVE SERVER (TCP HEALTH FIX)
# ==========================================
app = Flask('')

@app.route('/')
def home():
    return "Bot is Running! Status: Online"

def run_http():
    try:
        app.run(host='0.0.0.0', port=8000)
    except:
        pass

def keep_alive():
    t = Thread(target=run_http)
    t.daemon = True
    t.start()

# ==========================================
#  GLOBAL VARIABLES
# ==========================================
tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
#  HELPER FUNCTIONS
# ==========================================

def encrypt_packet(plain_text, key, iv):
    if isinstance(plain_text, str):
        data = plain_text.encode('utf-8')
    elif isinstance(plain_text, bytes):
        data = plain_text
    else:
        data = str(plain_text).encode('utf-8')

    if isinstance(key, str):
        try: key = bytes.fromhex(key)
        except: key = key.encode('utf-8')
    if isinstance(iv, str):
        try: iv = bytes.fromhex(iv)
        except: iv = iv.encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    try:
        a = zitado_get_proto(hexxx)
        if not a: return None
        data = json.loads(a)
        return data['5']['7']
    except: return None

def getownteam(hexxx):
    try:
        a = zitado_get_proto(hexxx)
        if not a: return None
        data = json.loads(a)
        return data['5']['1']

def get_player_status(packet):
    try:
        json_result = get_available_room(packet)
        parsed_data = json.loads(json_result)
        if "5" not in parsed_data or "data" not in parsed_data["5"]: return "OFFLINE"
        json_data = parsed_data["5"]["data"]
        if "1" not in json_data or "data" not in json_data["1"]: return "OFFLINE"
        data = json_data["1"]["data"]
        if "3" not in data: return "OFFLINE"
        status_data = data["3"]
        if "data" not in status_data: return "OFFLINE"
        status = status_data["data"]

        if status == 1: return "SOLO"
        if status == 2:
            if "9" in data and "data" in data["9"]:
                group_count = data["9"]["data"]
                countmax1 = data["10"]["data"]
                return f"INSQUAD ({group_count}/{countmax1 + 1})"
            return "INSQUAD"
        if status in [3, 5]: return "INGAME"
        if status == 4: return "IN ROOM"
        if status in [6, 7]: return "IN SOCIAL ISLAND MODE .."
        return "NOTFOUND"
    except: return "OFFLINE"

def get_idroom_by_idplayer(packet):
    try:
        json_result = get_available_room(packet)
        parsed_data = json.loads(json_result)
        return parsed_data["5"]["data"]["1"]["data"]['15']["data"]
    except: return 0

def get_leader(packet):
    try:
        json_result = get_available_room(packet)
        parsed_data = json.loads(json_result)
        return parsed_data["5"]["data"]["1"]["data"]['8']["data"]
    except: return 0

def generate_random_color():
    color_list = ["[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]", 
                  "[0000FF][b][c]", "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]"]
    return random.choice(color_list)

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit(): count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed

def fix_word(num):
    return fix_num(num) # Same logic needed

def check_banned_status(player_id):
    try:
        response = requests.get(f"http://mossa-api.vercel.app/check_banned?player_id={player_id}")
        return response.json() if response.status_code == 200 else {"error": "Failed"}
    except Exception as e: return {"error": str(e)}

def encode_varint(number):
    # Simplified varint encoder logic can be here, keeping original structure
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number: byte |= 0x80
        encoded_bytes.append(byte)
        if not number: break
    return bytes(encoded_bytes).hex()

def get_random_avatar():
    avatar_list = ['902000061', '902000060', '902000064', '902000065', '902000066', 
                   '902000074', '902000075', '902000077', '902000078', '902000084']
    return random.choice(avatar_list)

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        return json.dumps(parse_results(parsed_results))
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        else:
            field_data["data"] = result.data
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    try:
        final_result = hex(int(ask))[2:]
        if len(final_result) % 2 != 0:
            final_result = "0" + final_result
        return final_result
    except: return "00"

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()

def restart_program():
    # FIX: Termux crash fix - do nothing instead of os.execl
    print("[INFO] Connection Refreshing...")
    pass

# ==========================================
#  MAIN CLIENT CLASS (UPDATED)
# ==========================================

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        # Moved get_tok to run() to prevent blocking __init__

    def run(self):
        # Infinite Loop for Auto-Reconnect
        while True:
            try:
                print(f"[INFO] Connecting Account {self.id}...")
                self.get_tok()
            except Exception as e:
                print(f"[ERROR] Bot Crashed: {e}")
                print("[INFO] Restarting in 5 seconds...")
                time.sleep(5)

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak.hex() if isinstance(MajorLogRes.ak, bytes) else MajorLogRes.ak
            iv = MajorLogRes.aiv.hex() if isinstance(MajorLogRes.aiv, bytes) else MajorLogRes.aiv
            return getattr(MajorLogRes, "timestamp", 0), key, iv, getattr(MajorLogRes, "token", "")
        except Exception as e:
            print(f"Error parsing: {e}")
            return 0, None, None, ""
        
    def nmnmmmmn(self, data):
        try:
            key = bytes.fromhex(self.key) if isinstance(self.key, str) else self.key
            iv = bytes.fromhex(self.iv) if isinstance(self.iv, str) else self.iv
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(bytes.fromhex(data), AES.block_size)).hex()
        except: return ""

    # --- PACKET GENERATION (Helper methods) ---
    def wrap_packet(self, head, packet_hex):
        try:
            enc_packet = self.nmnmmmmn(packet_hex)
            header_len = len(bytes.fromhex(enc_packet))
            header_hex = dec_to_hex(header_len)
            
            # Dynamic padding for header
            prefix = "0515"
            if head == 78 or head == 6: prefix = "0E15"
            if head == 12: prefix = "1215" # Check logic
            
            # Simple header construction based on your original code logic
            if len(header_hex) == 2: return bytes.fromhex(prefix + "000000" + header_hex + enc_packet)
            elif len(header_hex) == 3: return bytes.fromhex(prefix + "00000" + header_hex + enc_packet)
            else: return bytes.fromhex(prefix + "0000" + header_hex + enc_packet)
        except: return b''

    def request_skwad(self, idplayer):
        fields = {1: 33, 2: {1: int(idplayer), 2: "IND", 3: 1, 4: 1, 7: 330, 8: 19459, 9: 100, 12: 1, 16: 1, 17: {2: 94, 6: 11, 8: "1.109.5", 9: 3, 10: 2}, 18: 201, 23: {2: 1, 3: 1}, 24: int(get_random_avatar()), 26: {}, 28: {}}}
        return self.wrap_packet(33, create_protobuf_packet(fields).hex())

    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {1: 4, 2: {1: int(ownerr), 3: int(idplayer), 4: "\u0001\u0007\t\n\u0012\u0019\u001a ", 8: 1, 9: {2: 1393, 4: "mossa", 6: 11, 8: "1.109.5", 9: 3, 10: 2}, 10: hashteam, 12: 1, 13: "en", 16: "OR"}}
        return self.wrap_packet(4, create_protobuf_packet(fields).hex())

    def start_autooo(self):
        fields = {1: 9, 2: {1: 11371687918}}
        return self.wrap_packet(9, create_protobuf_packet(fields).hex())

    def stauts_infoo(self, idd):
        fields = {1: 7, 2: {1: 11371687918}}
        # Note: Original code used 0515 prefix for status info, ensuring compatibility
        return self.wrap_packet(7, create_protobuf_packet(fields).hex())

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {1: 1, 2: {1: 12947146032, 2: Enc_Id, 3: 2, 4: str(Msg), 5: int(datetime.datetime.now().timestamp())}}
        packet = create_protobuf_packet(fields).hex()
        # Custom header for Message
        header_len = len(self.nmnmmmmn(packet)) // 2 # bytes len
        header_hex = dec_to_hex(header_len)
        padding = "0" * (8 - 4 - len(header_hex)) # 1215 is 4 chars
        return bytes.fromhex("1215" + padding + header_hex + self.nmnmmmmn(packet))

    # --- HEARTBEAT SYSTEM (REAL PLAYER) ---
    def heartbeat_loop(self, sock_conn):
        print("[System] Heartbeat & Anti-AFK Started ❤️")
        while True:
            try:
                time.sleep(45) # 45 Seconds Interval
                # Sending Status Info (Packet 7) to stay alive
                hb_packet = self.stauts_infoo(11371687918)
                sock_conn.send(hb_packet)
            except:
                break

    # --- GAME SOCKET CONNECTION ---
    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client, sent_inv, tempid, start_par, leaveee, pleaseaccept, tempdata, data22, statusinfo
        
        # Infinite Loop for Game Server Reconnect
        while True:
            try:
                socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) # Keep Connection Alive
                online_port = int(online_port)
                
                print(f"[Game] Connecting to {online_ip}:{online_port}")
                socket_client.connect((online_ip, online_port))
                socket_client.send(bytes.fromhex(tok))

                # Start Heartbeat in background
                hb_thread = threading.Thread(target=self.heartbeat_loop, args=(socket_client,))
                hb_thread.daemon = True
                hb_thread.start()

                while True:
                    data2 = socket_client.recv(9999)
                    if data2 == b"":
                        print("⚠️ Game Connection Closed. Reconnecting...")
                        socket_client.close()
                        break # Break inner loop to reconnect

                    hex_data = data2.hex()
                    
                    # --- Original Logic ---
                    if "0500" in hex_data[0:4]:
                        try:
                            accept_packet = f'08{hex_data.split("08", 1)[1]}'
                            kk = get_available_room(accept_packet)
                            parsed_data = json.loads(kk)
                            fark = parsed_data.get("4", {}).get("data", None)
                            
                            if fark == 18 and sent_inv:
                                aa = gethashteam(accept_packet)
                                ownerid = getownteam(accept_packet)
                                ss = self.accept_sq(aa, tempid, int(ownerid))
                                socket_client.send(ss)
                                sleep(1)
                                startauto = self.start_autooo()
                                socket_client.send(startauto)
                                start_par = False
                                sent_inv = False
                            
                            if fark == 6: leaveee = True
                            if fark == 50: pleaseaccept = True
                        except: pass
                    
                    if "0600" in hex_data[0:4] and len(hex_data) > 700:
                        try:
                            accept_packet = f'08{hex_data.split("08", 1)[1]}'
                            kk = get_available_room(accept_packet)
                            parsed = json.loads(kk)
                            global idinv, nameinv, senthi
                            idinv = parsed["5"]["data"]["1"]["data"]
                            nameinv = parsed["5"]["data"]["3"]["data"]
                            senthi = True
                        except: pass
                    
                    if "0f00" in hex_data[0:4]:
                        try:
                            packett = f'08{hex_data.split("08", 1)[1]}'
                            kk = get_available_room(packett)
                            parsed_data = json.loads(kk)
                            asdj = parsed_data["2"]["data"]
                            tempdata = get_player_status(packett)
                            
                            if asdj == 15:
                                if tempdata != "OFFLINE":
                                    idp = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                                    idp1 = fix_num(idp)
                                    if tempdata == "IN ROOM":
                                        idr = get_idroom_by_idplayer(packett)
                                        data22 = packett
                                        tempdata = f"id : {idp1}\nstatus : {tempdata}\nid room : {fix_num(idr)}"
                                    elif "INSQUAD" in tempdata:
                                        idl = get_leader(packett)
                                        tempdata = f"id : {idp1}\nstatus : {tempdata}\nleader id : {fix_num(idl)}"
                                    else:
                                        tempdata = f"id : {idp1}\nstatus : {tempdata}"
                                statusinfo = True
                        except: pass

            except Exception as e:
                print(f"[Game Error] {e}. Retrying in 2s...")
                time.sleep(2)
                continue

    # --- WHISPER SOCKET CONNECTION ---
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients, sent_inv, tempid, leaveee, start_par, nameinv, idinv, senthi, statusinfo, tempdata, pleaseaccept, tempdata1, data22
        
        while True: # Infinite Reconnect Loop for Whisper
            try:
                print(f"[Whisper] Connecting to {whisper_ip}:{whisper_port}")
                clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clients.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                clients.connect((whisper_ip, int(whisper_port)))
                clients.send(bytes.fromhex(tok))
                
                # Start Game Socket Thread only if not already running (simplified logic)
                # Ideally check thread, but for simplicity we restart it or let it handle itself.
                # Here we start it once per Whisper connection session.
                thread = threading.Thread(target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv))
                thread.daemon = True
                thread.start()

                while True:
                    data = clients.recv(9999)
                    if data == b"":
                        print("Whisper Connection Closed. Reconnecting...")
                        clients.close()
                        break 

                    hex_d = data.hex()

                    # --- COMMANDS ---
                    if "1200" in hex_d[0:4] and b"/glori" in data:
                        try:
                            json_result = get_available_room(hex_d[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            
                            cmd_split = re.split("/glori ", str(data))
                            if len(cmd_split) > 1:
                                player_id = cmd_split[1].split('(')[0].strip()
                                if "***" in player_id: player_id = player_id.replace("***", "106")
                                
                                if not player_id.isdigit():
                                    clients.send(self.GenResponsMsg(f"[FF0000]Invalid ID", uid))
                                    continue
                                
                                clients.send(self.GenResponsMsg(f"[00FF00]Started Spam {player_id}", uid))
                                
                                def send_spam():
                                    try:
                                        for i in range(50):
                                            inv = self.request_skwad(player_id)
                                            socket_client.send(inv)
                                            # RANDOM HUMAN DELAY
                                            time.sleep(random.uniform(0.5, 1.2))
                                            if (i+1)%10 == 0:
                                                clients.send(self.GenResponsMsg(f"Sent {i+1}", uid))
                                    except: pass
                                
                                t_spam = threading.Thread(target=send_spam)
                                t_spam.start()

                        except Exception as e: print(e)

            except Exception as e:
                print(f"[Whisper Error] {e}. Retrying in 2s...")
                time.sleep(2)
                continue

    # --- LOGIN & TOKEN ---
    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = json.loads(base64.urlsafe_b64decode(token_payload_base64).decode('utf-8'))
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = str(datetime.datetime.now())[:19]
        
        payload_hex = "1a13323032352d30372d30323031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033"
        payload = bytes.fromhex(payload_hex)
        
        payload = payload.replace(b"2025-07-02 11:02:51", now.encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        
        PAYLOAD = encrypt_api(payload.hex())
        return self.GET_LOGIN_DATA(JWT_TOKEN, bytes.fromhex(PAYLOAD))

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        attempt = 0
        while attempt < 3:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                json_result = get_available_room(response.content.hex())
                parsed = json.loads(json_result)
                
                w_addr = parsed['32']['data']
                o_addr = parsed['14']['data']
                
                return w_addr[:-6], int(w_addr[-5:]), o_addr[:-6], int(o_addr[-5:])
            except:
                attempt += 1
                time.sleep(2)
        return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4","Content-Type": "application/x-www-form-urlencoded"}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067"}
        
        res = requests.post(url, headers=headers, data=data).json()
        new_at = res['access_token']
        new_oid = res['open_id']
        old_at = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        old_oid = "996a629dbcdb3964be6b6978f5d814db"
        
        return self.TOKEN_MAKER(old_at, new_at, old_oid, new_oid, uid)
        
    def TOKEN_MAKER(self, OLD_AT, NEW_AT, OLD_OID, NEW_OID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        # Payload trimmed for brevity, original hex logic used in replace below
        data = bytes.fromhex('1a13323032352d30372d30323031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OID.encode(), NEW_OID.encode())
        data = data.replace(OLD_AT.encode(), NEW_AT.encode())
        
        Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        
        RES = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        ts, key, iv, b64_tok = self.parse_my_message(RES.content)
        w_ip, w_port, o_ip, o_port = self.GET_PAYLOAD_BY_DATA(b64_tok, NEW_AT, 1)
        return b64_tok, key, iv, ts, w_ip, w_port, o_ip, o_port

    def get_tok(self):
        # Authenticate and Connect
        token, key, iv, Timestamp, w_ip, w_port, o_ip, o_port = self.guest_token(self.id, self.password)
        
        decoded = jwt.decode(token, options={"verify_signature": False})
        acc_id = decoded.get('account_id')
        encoded_acc = hex(acc_id)[2:]
        time_hex = dec_to_hex(Timestamp)

        BASE64_TOKEN_ = token.encode()
        head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
        
        length = len(encoded_acc)
        zeros = '00000000'
        if length == 9: zeros = '0000000'
        elif length == 10: zeros = '000000'
        
        final_token = f'0115{zeros}{encoded_acc}{time_hex}00000{head}' + encrypt_packet(BASE64_TOKEN_, key, iv)
        self.connect(final_token, 'anything', key, iv, w_ip, w_port, o_ip, o_port)

if __name__ == "__main__":
    # 1. START TCP HEALTH CHECK SERVER
    keep_alive()
    
    # 2. START BOT ACCOUNTS
    try:
        # Aap aur bhi accounts add kar sakte hain isi tarah
        client1 = FF_CLIENT(id="4376930162", password="FEE1B5B06FAC1CCDB0323285925AD0728AF6AD7E2CEBB18DA96E24C2C9394323")
        client1.start()
        
        time.sleep(5) # Thoda gap dein taaki load na pade

        client2 = FF_CLIENT(id="4376960660", password="B67780B0841616DDBEC988F27333512EB89E066ACCC7AE2BB7AFA2DFBA4405FD")
        client2.start()

    except Exception as e:
        print(f"Main Error: {e}")
