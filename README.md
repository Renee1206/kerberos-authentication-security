# Kerberos Authentication Security

以 **Python** 實作 Kerberos 認證機制的互動式模擬系統，透過 **Tkinter GUI** 逐步呈現 Client、Authentication Server（AS）、Ticket Granting Server（TGS）與 Service Server 之間的驗證流程。

本專案除了模擬 Kerberos 的 Ticket-based Authentication，也加入 **AES 加密、Session Key、Timestamp 驗證、Replay Attack Detection、Mutual Authentication**，並額外展示 **RSA 數位簽章與 RSA 公私鑰加解密**。

---

## 功能特色

- 模擬 Kerberos AS / TGS / Service Server 認證流程
- 使用 AES 進行 Ticket 與 Session Key 加密
- 使用 SHA-256 將使用者密碼轉換為 AES Key
- 產生 Client–TGS 與 Client–Server Session Key
- 實作 Ticket Granting Ticket（TGT）
- 實作 Service Ticket
- 使用 Timestamp 驗證 Ticket 有效性
- 模擬 Replay Attack（重放攻擊）
- 超過時間容許範圍時自動拒絕認證
- 模擬 Client 與 Server Mutual Authentication
- 使用 RSA 2048-bit 公私鑰
- RSA 數位簽章與驗章
- RSA-OAEP 公鑰加密與私鑰解密
- Tkinter GUI 顯示完整認證過程與系統 Log

---

## Kerberos 認證流程

本系統將 Kerberos 認證流程分成以下階段：

```text
Client
  │
  │  1. Authentication Request
  ▼
Authentication Server (AS)
  │
  │  2. Session Key + TGT
  ▼
Client
  │
  │  3. TGT Request
  ▼
Ticket Granting Server (TGS)
  │
  │  4. Session Key + Service Ticket
  ▼
Client
  │
  │  5. Service Request
  ▼
Service Server
  │
  │  6. Mutual Authentication
  ▼
Client
```

### 1. Client → AS

Client 向 Authentication Server 發出認證請求。

使用者輸入：

- User ID
- Password

系統會將 Password 經過 SHA-256 處理後，取前 16 bytes 作為 AES Key。

---

### 2. AS → Client

Authentication Server 產生 Client 與 TGS 之間使用的 Session Key：

```text
Kc,tgs
```

同時建立 Ticket Granting Ticket：

```text
TGT = {
    Client ID,
    Session Key,
    Timestamp
}
```

TGT 會使用 TGS 的 Master Key 加密。

Session Key 與 TGT 則使用由使用者密碼產生的 AES Key 保護後傳回 Client。

因此，只有輸入正確密碼的 Client 才能成功解開 AS Response。

---

### 3. Client → TGS

Client 取得 TGT 後，將 Ticket 提交給 Ticket Granting Server，要求存取目標 Service Server。

---

### 4. TGS → Client

TGS 使用自己的 Master Key 解開 TGT，並驗證其中的 Timestamp。

驗證成功後，產生新的 Client–Server Session Key：

```text
Kc,v
```

以及 Service Ticket：

```text
Service Ticket = {
    Client ID,
    Session Key,
    Timestamp
}
```

Service Ticket 使用 Server Master Key 加密，Client 無法直接讀取 Ticket 內容。

---

### 5. Client → Server

Client 將取得的 Service Ticket 傳送至 Service Server，請求存取服務。

Server 使用自己的 Master Key 解開 Service Ticket，取得 Client–Server Session Key。

---

### 6. Mutual Authentication

Server 驗證 Service Ticket 後，以 Client–Server Session Key 加密：

```text
Timestamp + 1
```

並傳回 Client。

Client 成功解密並確認 Timestamp 後，即完成模擬的雙向認證流程。

---

## Replay Attack Detection

本系統內建 **Replay Attack 模擬模式**。

GUI 中勾選：

```text
模擬重放攻擊 (Timestamp -10m)
```

後，系統會故意將 TGT 的 Timestamp 設定為目前時間的 **10 分鐘前**。

程式設定允許的時間誤差為：

```python
TOLERANCE_SECONDS = 300
```

也就是 **5 分鐘**。

因此當 TGS 收到 10 分鐘前的 Ticket 時：

```text
10 minutes > 5 minutes tolerance
```

系統便會判定 Ticket 已過期，顯示：

```text
SECURITY ALERT
偵測到重放攻擊
```

並中斷認證流程。

---

## RSA 加密與數位簽章

完成 Kerberos 模擬認證之後，系統另外提供 RSA 密碼學功能展示。

### RSA Key Pair

系統動態產生：

```text
2048-bit RSA Private Key
2048-bit RSA Public Key
```

### Digital Signature

首先使用 SHA-256 計算訊息 Hash：

```text
Message
   ↓
SHA-256
   ↓
Hash
```

再使用 RSA Private Key 建立數位簽章：

```text
Private Key
     ↓
 Signature
```

最後使用 Public Key 驗證 Signature，以確認資料：

- Integrity（完整性）
- Authenticity（來源驗證）

### RSA Encryption

另外使用 RSA-OAEP 進行：

```text
Plaintext
   ↓
Public Key Encryption
   ↓
Ciphertext
   ↓
Private Key Decryption
   ↓
Plaintext
```

用以展示非對稱式密碼系統的基本運作方式。

---

## GUI

系統使用 Tkinter 建立圖形化操作介面。

認證流程共有：

```text
AS Req
   ↓
AS Resp
   ↓
TGS Req
   ↓
TGS Resp
   ↓
Server Req
   ↓
Mutual Auth
```

使用者可以透過按鈕逐步執行每個認證階段。

下方 Log 區域則會顯示：

- SYSTEM
- DEBUG
- SUCCESS
- SECURITY ALERT
- RSA

等不同類型的執行資訊，方便觀察加密、Ticket 產生及驗證過程。

---

## 使用技術

| 技術 | 用途 |
|---|---|
| Python | 主要開發語言 |
| Tkinter | GUI 使用者介面 |
| PyCryptodome | 密碼學相關功能 |
| AES | Ticket 與 Session Data 加密 |
| SHA-256 | Password / Message Hash |
| RSA | 非對稱式加密 |
| PKCS#1 v1.5 | RSA Digital Signature |
| RSA-OAEP | RSA Encryption |
| Base64 | Ciphertext / Key 編碼 |
| JSON | 認證資料結構 |

---

## 專案結構

```text
kerberos-authentication-security/
│
└── kerberos.py
```

### `kerberos.py`

主要程式，包含：

- `CryptoUtils`
  - AES Key 產生
  - Password → AES Key
  - AES Encryption
  - AES Decryption

- `KerberosUltimateGUI`
  - Tkinter GUI
  - Kerberos 認證狀態控制
  - Timestamp 驗證
  - Replay Attack Detection
  - Mutual Authentication
  - RSA Encryption
  - RSA Digital Signature

---

## 安裝方式

### 1. Clone Repository

```bash
git clone https://github.com/Renee1206/kerberos-authentication-security.git
cd kerberos-authentication-security
```

### 2. 安裝套件

本專案需要 `PyCryptodome`：

```bash
pip install pycryptodome
```

Tkinter 通常會隨 Python 一併安裝。

### 3. 執行程式

```bash
python kerberos.py
```

---

## 測試帳號

程式中預設的測試帳號資料為：

```text
User ID: group1
Password: abc123
```

啟動程式後輸入帳號與密碼，再透過 GUI 按鈕依序執行 Kerberos 認證流程。

---

## Replay Attack 測試

若要測試重放攻擊偵測：

1. 啟動程式
2. 輸入測試帳號與密碼
3. 勾選 `模擬重放攻擊 (Timestamp -10m)`
4. 開始執行認證流程
5. 執行至 TGS 驗證階段
6. 系統會偵測 Timestamp 已超過允許範圍
7. 顯示 `SECURITY ALERT` 並拒絕後續認證

---

## Security Mechanisms

本專案展示的資訊安全概念包含：

- Authentication
- Ticket-based Authentication
- Symmetric Encryption
- Asymmetric Encryption
- Session Key
- Password-based Key Generation
- Timestamp Verification
- Replay Attack Detection
- Mutual Authentication
- Digital Signature
- Message Integrity Verification

---

## 注意事項

本專案為 **資訊安全課程與密碼學概念展示用途**，並非正式的 Kerberos Protocol Implementation。

為了方便觀察認證流程，程式將 Client、AS、TGS 與 Server 模擬於同一個 Python Application 中，部分安全機制亦經過簡化。

---

## Project Purpose

透過實際程式模擬 Kerberos Authentication Protocol，了解：

1. Kerberos 如何避免直接傳送使用者密碼
2. Authentication Server 的角色
3. Ticket Granting Server 的角色
4. Ticket Granting Ticket 的用途
5. Session Key 如何建立
6. Service Ticket 如何進行服務驗證
7. Timestamp 如何降低 Replay Attack 風險
8. Mutual Authentication 的基本概念
9. 對稱式與非對稱式密碼系統的差異
10. RSA Digital Signature 的運作方式

---
