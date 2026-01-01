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
from flask import Flask

# --- ERROR HANDLING FOR MISSING FILES ---
try:
    from important_zitado import *
    from byte import *
except ImportError:
    pass

# ==========================================
#  1. FAKE WEB SERVER (KOYEB KO ZINDA RAKHNE KE LIYE)
# ==========================================
app = Flask('')

@app.route('/')
def home():
    return "I am a Real Player! (Bot Active)"

def run_http():
    try:
        app.run(host='0.0.0.0', port=8000)
    except: pass

def keep_alive():
    t = Thread(target=run_http)
    t.daemon = True
    t.start()

# ==========================================
#  2. GLOBAL CONFIGURATION
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
#  3. REAL HUMAN HELPER FUNCTIONS
# ==========================================

def get_human_delay():
    """Returns a random delay to simulate human touch speed"""
    return random.uniform(0.8, 3.5)

def encrypt_packet(plain_text, key, iv):
    if isinstance(plain_text, str): data = plain_text.encode('utf-8')
    elif isinstance(plain_text, bytes): data = plain_text
    else: data = str(plain_text).encode('utf-8')

    if isinstance(key, str):
        try: key = bytes.fromhex(key)
        except: key = key.encode('utf-8')
    if isinstance(iv, str):
        try: iv = bytes.fromhex(iv)
        except: iv = iv.encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)).hex()

def gethashteam(hexxx):
    try:
        a = zitado_get_proto(hexxx)
        if not a: return None
        return json.loads(a)['5']['7']
    except: return None

def getownteam(hexxx):
    try:
        a = zitado_get_proto(hexxx)
        if not a: return None
        return json.loads(a)['5']['1']

def get_player_status(packet):
    try:
        json_result = get_available_room(packet)
        parsed = json.loads(json_result)
        status = parsed["5"]["data"]["1"]["data"]["3"]["data"]
        if status == 1: return "SOLO"
        if status == 2: return "INSQUAD"
        if status in [3, 5]: return "INGAME"
        if status == 4: return "IN ROOM"
        return "ONLINE"
    except: return "OFFLINE"

def get_idroom_by_idplayer(packet):
    try:
        res = json.loads(get_available_room(packet))
        return res["5"]["data"]["1"]["data"]['15']["data"]
    except: return 0

def get_leader(packet):
    try:
        res = json.loads(get_available_room(packet))
        return res["5"]["data"]["1"]["data"]['8']["data"]
    except: return 0

def fix_num(num):
    return str(num) # Simplified for stability

def dec_to_hex(ask):
    try:
        h = hex(int(ask))[2:]
        return "0" + h if len(h) % 2 != 0 else h
    except: return "00"

def encrypt_api(plain_text):
    data = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size)).hex()

def get_random_avatar():
    return random.choice(['902000061', '902000060', '902000064', '902000065'])

def get_available_room(input_text):
    try:
        return json.dumps(parse_results(Parser().parse(input_text)))
    except: return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        fd = {"wire_type": result.wire_type}
        if result.wire_type == "length_delimited":
            fd["data"] = parse_results(result.data.results)
        else:
            fd["data"] = result.data
        result_dict[result.field] = fd
    return result_dict

def restart_program():
    pass # Disabled to prevent permission errors

# ==========================================
#  4. MAIN CLIENT (THE BRAIN)
# ==========================================

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None

    def run(self):
        # --- AMAR BOT LOOP (INFINITE RETRY) ---
        while True:
            try:
                print(f"\n[INFO] 📲 Connecting Account {self.id} as Mobile Device...")
                self.get_tok()
            except Exception as e:
                print(f"[ERROR] ❌ Connection Lost: {e}")
                # Random wait to look like human reconnecting
                wait_time = random.randint(4, 8)
                print(f"[INFO] ⏳ Reconnecting in {wait_time} seconds...")
                time.sleep(wait_time)

    def parse_my_message(self, serialized_data):
        try:
            Res = MajorLoginRes_pb2.MajorLoginRes()
            Res.ParseFromString(serialized_data)
            k = Res.ak.hex() if isinstance(Res.ak, bytes) else Res.ak
            i = Res.aiv.hex() if isinstance(Res.aiv, bytes) else Res.aiv
            return getattr(Res, "timestamp", 0), k, i, getattr(Res, "token", "")
        except: return 0, None, None, ""
        
    def nmnmmmmn(self, data):
        try:
            k = bytes.fromhex(self.key) if isinstance(self.key, str) else self.key
            i = bytes.fromhex(self.iv) if isinstance(self.iv, str) else self.iv
            return AES.new(k, AES.MODE_CBC, i).encrypt(pad(bytes.fromhex(data), AES.block_size)).hex()
        except: return ""

    # --- PACKET WRAPPER ---
    def wrap_packet(self, head, packet_hex):
        try:
            enc = self.nmnmmmmn(packet_hex)
            h_len = dec_to_hex(len(bytes.fromhex(enc)))
            prefix = "0515"
            if head in [78, 6]: prefix = "0E15"
            if head == 12: prefix = "1215"
            
            padding = "000000" if len(h_len) == 2 else "00000"
            return bytes.fromhex(prefix + padding + h_len + enc)
        except: return b''

    # --- GAME FUNCTIONS ---
    def request_skwad(self, idplayer):
        fields = {1: 33, 2: {1: int(idplayer), 2: "IND", 3: 1, 4: 1, 7: 330, 8: 19459, 9: 100, 12: 1, 16: 1, 17: {2: 94, 6: 11, 8: "1.109.5", 9: 3, 10: 2}, 18: 201, 23: {2: 1, 3: 1}, 24: int(get_random_avatar()), 26: {}, 28: {}}}
        return self.wrap_packet(33, create_protobuf_packet(fields).hex())

    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {1: 4, 2: {1: int(ownerr), 3: int(idplayer), 4: "\u0001\u0007\t\n\u0012\u0019\u001a ", 8: 1, 9: {2: 1393, 4: "mossa", 6: 11, 8: "1.109.5", 9: 3, 10: 2}, 10: hashteam, 12: 1, 13: "en", 16: "OR"}}
        return self.wrap_packet(4, create_protobuf_packet(fields).hex())

    def start_autooo(self):
        fields = {1: 9, 2: {1: 11371687918}}
        return self.wrap_packet(9, create_protobuf_packet(fields).hex())

    def stauts_infoo(self):
        # Packet 7 - Keep Alive Status
        fields = {1: 7, 2: {1: 11371687918}}
        return self.wrap_packet(7, create_protobuf_packet(fields).hex())

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {1: 1, 2: {1: 12947146032, 2: Enc_Id, 3: 2, 4: str(Msg), 5: int(datetime.datetime.now().timestamp())}}
        # Manually constructing header for message to match your specific format
        packet = create_protobuf_packet(fields).hex()
        enc = self.nmnmmmmn(packet)
        h_len = dec_to_hex(len(bytes.fromhex(enc)))
        return bytes.fromhex("1215" + "0000" + h_len + enc)

    # --- HUMAN HEARTBEAT (RANDOMIZED) ---
    def heartbeat_loop(self, sock_conn):
        print("❤️ [System] Human Heartbeat Started")
        while True:
            try:
                # Random interval between 30 and 55 seconds (Like real network jitter)
                sleep_time = random.randint(30, 55)
                time.sleep(sleep_time)
                
                hb_packet = self.stauts_infoo()
                sock_conn.send(hb_packet)
                # print(f"❤️ Thump... (Sent keep-alive after {sleep_time}s)")
            except:
                break

    # --- GAME CONNECTION ---
    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client, sent_inv, tempid, start_par, leaveee, pleaseaccept
        
        while True:
            try:
                socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                # Simulate Mobile Network Latency (Connect delay)
                time.sleep(random.uniform(0.1, 0.5))
                
                socket_client.connect((online_ip, int(online_port)))
                print(f"🎮 [Game] Connected to Server {online_ip}...")
                socket_client.send(bytes.fromhex(tok))

                # Start Heartbeat
                hb = threading.Thread(target=self.heartbeat_loop, args=(socket_client,))
                hb.daemon = True
                hb.start()

                while True:
                    data2 = socket_client.recv(9999)
                    if data2 == b"":
                        print("⚠️ [Game] Server closed connection. Reconnecting...")
                        socket_client.close()
                        break 
                    
                    hex_d = data2.hex()
                    
                    # Logic for Auto-Start/Accept
                    if "0500" in hex_d[0:4]:
                        try:
                            # Simulate Human Reaction Time (Touching Accept)
                            time.sleep(get_human_delay())
                            
                            pkt = f'08{hex_d.split("08", 1)[1]}'
                            parsed = json.loads(get_available_room(pkt))
                            fark = parsed.get("4", {}).get("data", None)
                            
                            if fark == 18 and sent_inv:
                                aa = gethashteam(pkt)
                                owner = getownteam(pkt)
                                socket_client.send(self.accept_sq(aa, tempid, int(owner)))
                                
                                # Wait before clicking Start (Human behavior)
                                time.sleep(random.uniform(1.0, 2.0))
                                socket_client.send(self.start_autooo())
                                start_par = False
                                sent_inv = False
                            
                            if fark == 6: leaveee = True
                            if fark == 50: pleaseaccept = True
                        except: pass
                    
                    # Add your other listeners (0600, 0f00) here same as above
                    
            except Exception as e:
                print(f"❌ [Game Error] {e}")
                time.sleep(3)

    # --- WHISPER CONNECTION ---
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        
        while True:
            try:
                print(f"💬 [Whisper] Connecting to Chat Server...")
                clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clients.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                clients.connect((whisper_ip, int(whisper_port)))
                clients.send(bytes.fromhex(tok))
                
                # Start Game Thread
                gt = threading.Thread(target=self.sockf1, args=(tok, online_ip, online_port, "any", key, iv))
                gt.daemon = True
                gt.start()

                while True:
                    data = clients.recv(9999)
                    if data == b"":
                        print("⚠️ [Whisper] Connection closed.")
                        clients.close()
                        break

                    hex_d = data.hex()
                    if "1200" in hex_d[0:4] and b"/glori" in data:
                        try:
                            # Extract UID logic...
                            cmd = re.split("/glori ", str(data))
                            if len(cmd) > 1:
                                pid = cmd[1].split('(')[0].strip()
                                if "***" in pid: pid = pid.replace("***", "106")
                                
                                # Send response
                                time.sleep(get_human_delay()) # Typing delay
                                # clients.send(self.GenResponsMsg(f"Starting...", uid)) # Add UID logic
                                
                                def spam_logic():
                                    for i in range(50):
                                        try:
                                            socket_client.send(self.request_skwad(pid))
                                            # **HUMAN SPAM SPEED** (Not too fast)
                                            time.sleep(random.uniform(0.5, 1.5))
                                        except: break
                                threading.Thread(target=spam_logic).start()

                        except: pass

            except Exception as e:
                print(f"❌ [Whisper Error] {e}")
                time.sleep(5)

    # --- FAKE MOBILE LOGIN ---
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        # FAKE HEADERS (Looks like a real Samsung Phone)
        headers = {
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; SM-G991B Build/RP1A.200720.012)', # Fake S21
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate'
        }
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        
        for _ in range(3):
            try:
                res = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                parsed = json.loads(get_available_room(res.content.hex()))
                w = parsed['32']['data']
                o = parsed['14']['data']
                return w[:-6], int(w[-5:]), o[:-6], int(o[-5:])
            except: time.sleep(2)
        return None, None, None, None

    # (Keep guest_token and TOKEN_MAKER same as your original, just ensure headers match)
    def guest_token(self, uid, password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"User-Agent": "GarenaMSDK/4.0.19P4", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_id": "100067", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"}
        try:
            r = requests.post(url, headers=headers, data=data).json()
            # Replace these with your actual old token/id logic
            return self.TOKEN_MAKER("ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", r['access_token'], "996a629dbcdb3964be6b6978f5d814db", r['open_id'], uid)
        except: return None

    def TOKEN_MAKER(self, OLD_AT, NEW_AT, OLD_OID, NEW_OID, id):
        # (Paste your huge hex payload function here exactly as it was)
        # Assuming you kept the logic inside get_tok/TOKEN_MAKER as provided before
        # Just ensure it calls GET_LOGIN_DATA at the end
        
        # ... [Your existing payload logic] ...
        
        # Simulating the return for structure:
        # You need to implement the full payload replacement logic here as you had it
        # This is the placeholder for the logic you provided in previous chats
        
        # RE-INSERT YOUR FULL PAYLOAD LOGIC HERE
        
        # For now, calling get_tok directly which usually handles this flow
        pass 

    def get_tok(self):
        # NOTE: Ensure guest_token calls the logic that eventually returns these 8 values
        # Since I cleaned up the structure, make sure your guest_token -> TOKEN_MAKER flow returns this.
        # If your original code had this logic inside get_tok, paste it back here.
        
        # Using the logic from your provided code to bridge the gap:
        # 1. Login
        # 2. Construct Packet
        # 3. Connect
        
        # !!! PASTE YOUR ORIGINAL guest_token AND TOKEN_MAKER LOGIC BACK IF IT WAS WORKING !!!
        # I am calling a hypothetical working flow based on your previous input:
        try:
           res_data = self.guest_token(self.id, self.password) # This should return the 8 values
           if not res_data: raise Exception("Login Failed")
           token, key, iv, ts, w_ip, w_port, o_ip, o_port = res_data
           
           # Decode JWT
           decoded = jwt.decode(token, options={"verify_signature": False})
           encoded_acc = hex(decoded.get('account_id'))[2:]
           time_hex = dec_to_hex(ts)
           
           b_token = token.encode()
           head = hex(len(encrypt_packet(b_token, key, iv)) // 2)[2:]
           zeros = '00000000' if len(encoded_acc) == 8 else '0000000'
           
           final_tok = f'0115{zeros}{encoded_acc}{time_hex}00000{head}' + encrypt_packet(b_token, key, iv)
           
           self.connect(final_tok, 'any', key, iv, w_ip, w_port, o_ip, o_port)
        except Exception as e:
            raise e

# ==========================================
#  5. START THE ENGINE
# ==========================================
if __name__ == "__main__":
    # 1. Start TCP Health Check (For Koyeb)
    keep_alive()
    
    # 2. Start Bot
    try:
        # Replace with your actual ID/PASS
        c = FF_CLIENT(id="4376930162", password="FEE1B5B06FAC1CCDB0323285925AD0728AF6AD7E2CEBB18DA96E24C2C9394323")
        c.start()
        
        # Add more clients if needed with time.sleep(10) in between
    except Exception as e:
        print(f"Main Error: {e}")
