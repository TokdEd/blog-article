# 🧠 CTF 題解分析：PRNG 預測與時間棧推測

---

## 📘 題目簡介

本題是一道結合「PRNG 預測」與「時間棧推測」的 CTF 題目。  
儘管題目中有格式字串漏洞，但主要攻擊路徑不在於記憶體讀寫，  
而是利用伺服器使用 `time(NULL)` 作為亂數種子的弱點，成功預測 secret 並取得 shell。

---

## 🔍 題目程式邏輯簡述

- 使用 `srand(time(NULL))` 設定亂數種子  
- 使用 `rand()` 從 `charset` 中選出 15 個字元組合成 `secret`  
- 使用者輸入 `buf` 後，程式會執行 `printf(buf)`  
- 若使用者接著輸入 `y` 且 `buf == secret`，即可進入 shell  
- 成功進入 shell 後，可執行 `cat /flag.txt` 取得 flag  

---

## 🔢 PRNG 原理解析

### ✅ 什麼是 PRNG？

PRNG（Pseudo-Random Number Generator，偽隨機數生成器）是一種由數學函式決定的「看似隨機」的數列生成方式。  
但本質上是可預測的，因為：

- PRNG 是由一個「種子（seed）」決定的  
- 相同的 seed 會產出相同的數列  

### ✅ 題目使用的 PRNG

```c
srand(time(NULL));  // 以時間為種子初始化亂數
rand();             // 生成 pseudo-random 整數
```
由於 time(NULL) 傳回的是「秒級」的 UNIX timestamp，例如：

1713712345, 1713712346, ...

➡️ 只要知道伺服器產生 secret 的時間，就能完全預測 PRNG 輸出。

---

## ⌛ 時間棧（Time Stack）推測法

### 📌 什麼是時間棧？

「時間棧」指的是一段推測出來的伺服器可能使用的 time(NULL) 時間種子集合。
由於精度是秒，所以這個集合可以小到只有 5 個可能值。

範例：如果你在 1713712345 秒發起請求，伺服器產生 PRNG 的時間可能落在：

```
[1713712343, 1713712344, 1713712345, 1713712346, 1713712347]
```


---

### 📈 時間棧暴力邏輯流程
1.	偵測「目前時間戳」（使用 time.time() 取整數）
2.	建立時間棧區間（例如 ±2 秒）
3.	對每個時間 seed 模擬伺服器產生 secret 的邏輯：
-	使用 srand(seed)
-	執行 15 次 rand() %len(charset) 模擬 secret
4.	連線伺服器，輸入預測出的 secret 作為 buf
5.	送出 y，觸發 strcmp(buf, secret)
6.	若命中，即可進入 shell 拿 flag

---

## 🔗 攻擊邏輯鏈（清晰有條理）

| 步驟               | 說明                                                        |
|--------------------|-------------------------------------------------------------|
| 🔍 找弱點          | PRNG 使用 `time(NULL)`，秒級精度容易預測                   |
| 📐 定義時間棧       | 預估伺服器產生 secret 的時間 ±2 秒                          |
| 🛠️ 模擬生成        | 使用同樣種子模擬 `rand()` 邏輯產出候選 secret              |
| 📤 試輸入           | 把每個候選值當作 buf 輸入                                   |
| ✅ 命中比對成功     | `strcmp(buf, secret)` 為真，進入 shell                      |
| 🏁 拿到 flag        | 輸入 `cat /flag.txt` 拿到題目 flag                         |


---

🧪 實作範例（Python 模擬）

```Python

from pwn import *
import time, string, random

charset = string.ascii_letters + string.digits

def generate_secret(seed):
    random.seed(seed)
    return ''.join(random.choice(charset) for _ in range(15))

now = int(time.time())

for offset in range(-2, 3):
    guess_seed = now + offset
    secret = generate_secret(guess_seed)

    io = remote("host", 1337)
    io.sendline(secret)
    io.sendline("y")

    try:
        io.sendline("cat /flag.txt")
        flag = io.recv()
        if b"flag" in flag:
            print("[+] Found:", flag)
            break
    except:
        io.close()

```

---

## 🧾 題目特色與結語

| 元素           | 說明                                               |
|----------------|----------------------------------------------------|
| ⚠️ 格式字串     | 雖然存在，但並非主攻路徑                           |
| 🧬 PRNG 弱點    | `srand(time(NULL))` 是核心漏洞                     |
| 🕰️ 時間棧法     | 秒級時間可準確預測，暴力空間極小                   |
| 🛠️ 技術門檻     | 需理解 `rand()` 邏輯與時間行為                    |
| 🧨 攻擊型態     | 預測、爆破、比對、提權、取 flag                   |

---


## 📌 重點回顧（Checklist）
1. ✅ PRNG 原理清楚理解
2. ✅ srand(time(NULL)) 弱點掌握
3. ✅ 時間棧（time stack）概念清晰
4. ✅ 成功模擬 PRNG 預測
5. ✅ 攻擊邏輯完整可驗證

---

## 📚 延伸學習建議
- 如何使用格式字串漏洞做記憶體讀寫（若條件允許）
- 更複雜的 PRNG（如 Mersenne Twister）預測方法
- 使用 strace 或 gdb 還原 rand() 行為

---



