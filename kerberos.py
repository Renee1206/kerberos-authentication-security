import time, json, base64, tkinter as tk  
from tkinter import scrolledtext 
from Crypto.Cipher import AES  
from Crypto.PublicKey import RSA 
from Crypto.Signature import pkcs1_15 
from Crypto.Hash import SHA256  
from Crypto.Util.Padding import pad, unpad 
from Crypto.Random import get_random_bytes 
from Crypto.Cipher import PKCS1_OAEP  

# ==========================================
# AES 加密與解密工具類別
# ==========================================
class CryptoUtils:
    @staticmethod
    def get_key(): 
        return get_random_bytes(16) # 隨機產生 16 bytes（128bits）的 AES 金鑰

    @staticmethod
    def password_to_aes_key(password):
        # 把密碼雜湊成 256 位元，然後只取前 16 位元組當 AES 金鑰
        return SHA256.new(password.encode('utf-8')).digest()[:16]

    @staticmethod
    def aes_encrypt(msg_dict, key, logger=None):
        # 將字典轉換成 JSON 字串
        plaintext_json = json.dumps(msg_dict, indent=2, ensure_ascii=False)
        if logger: logger("DEBUG", f"加密前明文:\n{plaintext_json}")

        cipher = AES.new(key, AES.MODE_ECB) # 初始化 AES 
        msg_str = json.dumps(msg_dict)
        # 填充後加密
        ciphertext = cipher.encrypt(pad(msg_str.encode('utf-8'), AES.block_size))
        # 轉成 Base64 字串
        encoded_cipher = base64.b64encode(ciphertext).decode('utf-8')

        if logger: logger("DEBUG", f"加密後密文: {encoded_cipher[:30]}...")
        return encoded_cipher

    @staticmethod
    def aes_decrypt(ciphertext_b64, key):
        # 把 Base64 轉回來，解密，並去掉填充
        cipher = AES.new(key, AES.MODE_ECB)
        decoded_data = unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)), AES.block_size)
        return json.loads(decoded_data.decode('utf-8')) # 把 JSON 字串轉回 Python 字典

# 模擬資料庫與master key
DB_USER_ID = "group1"
DB_USER_PASSWORD = "abc123"
TGS_MASTER_KEY = b'9876543210987654'   # TGS 伺服器自己的私鑰
SERVER_MASTER_KEY = b'abcdefghijklmnop' # 最終服務伺服器的私鑰
TOLERANCE_SECONDS = 300  # 允許的時間誤差

class KerberosUltimateGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Kerberos V4 Ultimate Security Demo")
        self.root.geometry("850x750")
        self.step = 0        
        self.data = {}       

        # header, 輸入帳密
        header = tk.Frame(root, pady=10)
        header.pack()
        tk.Label(header, text="User ID:").grid(row=0, column=0)
        self.entry_id = tk.Entry(header); self.entry_id.insert(0, "")
        self.entry_id.grid(row=0, column=1, padx=5)
        tk.Label(header, text="Password:").grid(row=0, column=2)
        self.entry_pass = tk.Entry(header, show="*"); self.entry_pass.insert(0, "")
        self.entry_pass.grid(row=0, column=3, padx=5)
        
        # 模擬攻擊勾選
        self.attack_var = tk.BooleanVar()
        self.chk_attack = tk.Checkbutton(header, text="模擬重放攻擊 (Timestamp -10m)", variable=self.attack_var, fg="red", font=("Arial", 9, "bold"))
        self.chk_attack.grid(row=1, column=0, columnspan=4, pady=5)

        self.btn_next = tk.Button(root, text="開始認證流程", command=self.next_step, bg="#008CBA", fg="white", font=("Arial", 10, "bold"), width=30)
        self.btn_next.pack(pady=5)

        # 流程指示燈
        self.status_frame = tk.Frame(root)
        self.status_frame.pack(pady=5)
        self.indicators = []
        steps_text = ["AS Req", "AS Resp", "TGS Req", "TGS Resp", "Server Req", "Mutual Auth"]
        for text in steps_text:
            lbl = tk.Label(self.status_frame, text=text, bg="lightgrey", width=12, relief="sunken", font=("Arial", 8))
            lbl.pack(side=tk.LEFT, padx=2)
            self.indicators.append(lbl)

        # 日誌顯示區
        self.log_area = scrolledtext.ScrolledText(root, width=105, height=35, bg="#2b2b2b", fg="#d1d1d1", font=("Consolas", 9))
        self.log_area.pack(padx=10, pady=10)

    def log(self, tag, msg):
        # 不同的日誌層級上顏色
        color = "#d1d1d1"
        if "DEBUG" in tag: color = "#61afef"
        if "SECURITY ALERT" in tag: color = "#ff0015"
        if "SUCCESS" in tag: color = "#98c379"
        if "SYSTEM" in tag: color = "#e5c07b"
        
        self.log_area.tag_config(tag, foreground=color)
        self.log_area.insert(tk.END, f"[{tag}] {msg}\n", tag)
        self.log_area.see(tk.END)

    def set_active(self, index):
        # 切換指示燈顏色
        for i, lbl in enumerate(self.indicators):
            lbl.config(bg="#4CAF50" if i == index else "lightgrey", fg="white" if i == index else "black")

    def verify_timestamp(self, ts, role):
        # 如果時間差太遠，就代表這封包可能是被攔截後重發的
        diff = abs(time.time() - ts)
        if diff > TOLERANCE_SECONDS:
            self.log("SECURITY ALERT", f"偵測到重放攻擊！時間差 {diff:.1f} 秒已超過門檻。")
            return False
        self.log("SUCCESS", f"{role} 驗證時間戳記通過 (誤差: {diff:.2f}s)。")
        return True

    def next_step(self):
        # 這是一個狀態機，控制 Kerberos 的每個對話階段
        uid = self.entry_id.get().strip()
        upass = self.entry_pass.get().strip()

        if self.step == 0:
            # 初始化
            self.log_area.delete(1.0, tk.END)
            self.data['user_key'] = CryptoUtils.password_to_aes_key(upass)
            self.log("SYSTEM", f"初始化成功。攻擊模式: {'開啟' if self.attack_var.get() else '關閉'}")
            self.btn_next.config(text="1. Client -> AS (Request)")
            self.step = 1

        elif self.step == 1:
            # 階段一：客戶端跟認證伺服器 (AS) 打招呼
            self.set_active(0)
            self.log("Phase 1", "Client 向 AS 請求認證...")
            self.btn_next.config(text="2. AS -> Client (Response)")
            self.step = 2

        elif self.step == 2:
            # 階段二：AS 回傳用用戶密碼加密過的訊息，以及 TGT (給 TGS 看的票)
            self.set_active(1)
            s_key_tgs = CryptoUtils.get_key() # 產生 Client 與 TGS 溝通用的臨時金鑰
            
            # 如果按了攻擊模式，故意把時間設成 10 分鐘前
            ts = time.time() - 600 if self.attack_var.get() else time.time()
            
            # TGT 包含 Client ID、Session Key 和時間，用 TGS 的金鑰加密
            tgt_info = {"client": uid, "session_key": base64.b64encode(s_key_tgs).decode('utf-8'), "timestamp": ts}
            tgt = CryptoUtils.aes_encrypt(tgt_info, TGS_MASTER_KEY, self.log)
            
            # 將 Session Key 與 TGT 包裝後，用「用戶密碼」加密傳給用戶
            as_resp = CryptoUtils.aes_encrypt({"session_key": base64.b64encode(s_key_tgs).decode('utf-8'), "ticket_tgs": tgt}, CryptoUtils.password_to_aes_key(DB_USER_PASSWORD), self.log)
            
            try:
                # 用戶嘗試用自己輸入的密碼解密，解不開就代表密碼錯了
                resp = CryptoUtils.aes_decrypt(as_resp, self.data['user_key'])
                self.data['key_c_tgs'] = base64.b64decode(resp['session_key'])
                self.data['tgt'] = resp['ticket_tgs']
                self.log("Client", "解密 AS 回傳成功，取得 TGT。")
                self.btn_next.config(text="3. Client -> TGS (Request)")
                self.step = 3
            except:
                self.log("SECURITY ALERT", "密碼不匹配，無法解密 AS 回應！")
                self.step = 0

        elif self.step == 3:
            # 階段三：用戶拿著 TGT 去找票據授權伺服器 (TGS) 換服務票
            self.set_active(2)
            self.log("Phase 2", "Client 持 TGT 尋找 TGS 換票...")
            self.btn_next.config(text="4. TGS -> Client (Response)")
            self.step = 4

        elif self.step == 4:
            # 階段四：TGS 驗證 TGT，然後發放 Service Ticket
            self.set_active(3)
            # TGS 用自己的金鑰解開 TGT
            tgt_data = CryptoUtils.aes_decrypt(self.data['tgt'], TGS_MASTER_KEY)
            # 檢查票據有沒有過期
            if not self.verify_timestamp(tgt_data['timestamp'], "TGS"):
                self.log("SYSTEM", "認證中斷：系統偵測到過期票據，拒絕服務。")
                self.btn_next.config(text="認證失敗 (重置)", bg="red")
                self.step = 99
                return

            s_key_v = CryptoUtils.get_key() # 產生 Client 與 Server 溝通用的 Session Key
            # 製作 Service Ticket，用 Server 的主金鑰加密
            t_v_info = {"client": uid, "session_key": base64.b64encode(s_key_v).decode('utf-8'), "timestamp": time.time()}
            ticket_v = CryptoUtils.aes_encrypt(t_v_info, SERVER_MASTER_KEY, self.log)
            # 把 Session Key 和 Ticket 傳回給 Client
            tgs_resp = CryptoUtils.aes_encrypt({"session_key": base64.b64encode(s_key_v).decode('utf-8'), "ticket_v": ticket_v}, self.data['key_c_tgs'], self.log)
            
            resp = CryptoUtils.aes_decrypt(tgs_resp, self.data['key_c_tgs'])
            self.data['key_c_v'] = base64.b64decode(resp['session_key'])
            self.data['ticket_v'] = resp['ticket_v']
            self.log("TGS", "驗證成功，發放 Service Ticket。")
            self.btn_next.config(text="5. Client -> Server (Request)")
            self.step = 5

        elif self.step == 5:
            # 階段五：用戶拿著 Service Ticket 去找真正的 Server 請求服務
            self.set_active(4)
            self.data['now'] = time.time()
            self.log("Phase 3", "Client 請求 Server 資源服務...")
            self.btn_next.config(text="6. Server -> Client (Mutual Auth)")
            self.step = 6

        elif self.step == 6:
            # 階段六：Server 驗證票據，並進行雙向認證
            self.set_active(5)
            # Server decode Ticket
            v_data = CryptoUtils.aes_decrypt(self.data['ticket_v'], SERVER_MASTER_KEY)
            if not self.verify_timestamp(v_data['timestamp'], "Server"):
                self.log("SYSTEM", "伺服器判定此請求為攻擊，存取拒絕。")
                self.step = 99
                return

            # 雙向認證：Server 把時間戳記 + 1 再傳回去，證明自己真的是 Server
            resp = CryptoUtils.aes_encrypt({"timestamp_plus_one": self.data['now'] + 1}, self.data['key_c_v'], self.log)
            final = CryptoUtils.aes_decrypt(resp, self.data['key_c_v'])
            self.log("SUCCESS", f"雙向驗證完成！Server 回傳 TS+1: {final['timestamp_plus_one']}")
            self.btn_next.config(text="7. 展示 RSA 簽章")
            self.step = 7

        elif self.step == 7:
            self.log("RSA", "=== 進入 RSA 階段 (加密與簽章) ===")
            
            # 1. 生成金鑰對
            key = RSA.generate(2048)
            private_key = key
            public_key = key.publickey()
            self.log("RSA", "已生成 2048-bit RSA 公私鑰對。")

            # ---------------------------
            # A: RSA 數位簽章 (Signature)
            # ---------------------------
            msg_sign = b"Report Integrity Check"
            h = SHA256.new(msg_sign)
            signature = pkcs1_15.new(private_key).sign(h)
            
            try:
                pkcs1_15.new(public_key).verify(h, signature)
                self.log("SUCCESS", "[簽章測試] 簽章驗證成功")
            except:
                self.log("ERROR", "[簽章測試] 驗證失敗！")

            # ---------------------------
            # B : RSA 加密 (Encryption)
            # ---------------------------
            msg_encrypt = b"Secret Session Key 12345"
            self.log("RSA", f"[加密測試] 原始訊息: {msg_encrypt.decode()}")

            # (A) 公鑰加密
            cipher_rsa = PKCS1_OAEP.new(public_key)
            enc_data = cipher_rsa.encrypt(msg_encrypt)
            self.log("RSA", f"[加密測試] 加密後長度: {len(enc_data)} bytes")
            self.log("RSA", f"[加密測試] 加密後訊息: {enc_data}")

            # (B) 私鑰解密
            decipher_rsa = PKCS1_OAEP.new(private_key)
            dec_data = decipher_rsa.decrypt(enc_data)
            
            if dec_data == msg_encrypt:
                self.log("SUCCESS", f"[加密測試] 解密成功 (Encryption Scheme OK): {dec_data.decode()}")
            else:
                self.log("ERROR", "[加密測試] 解密失敗！")

            self.btn_next.config(text="演示結束 (重置)", bg="grey")
            self.step = 8
        else:
            # 重設流程: step=0
            self.step = 0
            self.btn_next.config(text="開始認證流程", bg="#008CBA")
            for lbl in self.indicators: lbl.config(bg="lightgrey", fg="black")

if __name__ == "__main__":
    root = tk.Tk()
    app = KerberosUltimateGUI(root)
    root.mainloop() 