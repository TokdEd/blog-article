# 🧠 CTF 題解分析：time_GEM ELF 可執行檔解密

---

## 📘問題背景

在解決此問題時，我們分析了 ELF 格式的 time_GEM 可執行檔。程式內包含一段加密邏輯，其中透過 XOR 操作結合了靜態資料與字串，並且存在 sleep() 造成執行時間過長的問題。為了解決這個問題，我們需要跳過延遲時間並重新實現加密邏輯，從而快速計算出結果。

---

## 🔍關鍵概念：偏移（Offset）

在進行 ELF 分析時，理解偏移的概念是關鍵。偏移指的是從某個基準點（通常是記憶體或檔案的開頭）開始的距離。通常，在二進位檔案（如 ELF 檔案）中，偏移用來標示資料在檔案內的具體位置。

例如，在 ELF 檔案中的某個資料段（如 .rodata）開始於某個地址（假設是 0x2000）。如果某個資料的偏移為 0x60，那麼該資料的絕對位置將是 0x2000 + 0x60 = 0x2060。這個偏移量可以幫助我們從二進位檔案中提取出對應的資料。

在本題中，資料 unk_2060 在 ELF 檔案中的偏移是 0x2060，其對應的資料長度為 264 位元組。因此，我們可以透過以下命令將其從二進位檔案中提取出來：

dd if=time_GEM bs=1 skip=8288 count=264 of=data.bin

此命令的 skip=8288 表示從位址 0x2060 開始提取資料。

---

## 程式分析

---

### main 函數

main 函數簡單地輸出一些介紹文字，然後呼叫 time_gem() 函數。這是程式的主要執行流程。

---

### time_gem 函數

time_gem 函數調用 power() 函數並返回其結果，這部分是實現加密邏輯的關鍵。

---

### power 函數

power 函數中包含了處理加密邏輯的核心部分。具體步驟如下：
1.	資料初始化：
-	qmemcpy(v10, &unk_2060, 0x108u); 將 264 位元組（0x108）從資料區段 unk_2060 複製到緩衝區 v10 中，v10 是一個包含 70 個 32 位元整數的陣列（總共 280 位元組）。
-	v10[66] = unk_2168; 設定 v10 中的第 67 個元素為 unk_2168 的值。
2.	主要加密循環：
-	透過 

```
for ( i = 0; i < v4; ++i )
```

 進行 67 次迴圈，每次計算一個 flag 字元。
-	每次循環中，會使用字串 
```
s = "THJCCISSOGOODIMNOTTHEFLAG!!!" 
```
與迴圈索引 i 做 XOR 計算，然後與 v10[i] 中的最低位元組做 XOR，再得到最終的字元。

```c++
v6 = s[i % v5] ^ (i % 256);
*((_BYTE *)v9 + i) = v6 ^ LOBYTE(v10[i]);
printf("%c\n", (unsigned int)*((char *)v9 + i));
```

這段程式碼的核心是透過 XOR 操作將字串中的每個字元與資料中的值進行運算，從而生成加密結果。

3.	延遲處理：
-	最後，程式會進行長時間的 sleep()，使得執行時間非常長（約 3.8 天）。這是問題的一部分，使得直接執行無法快速獲得 flag。

---

### 解題思路
1.	提取資料：
-	使用 objdump 等工具獲取 ELF 檔案的結構，從中提取出 unk_2060 和 unk_2168 的資料，這些資料對應了程式中的關鍵數據。
2.	跳過延遲時間：
-	由於 sleep() 使得執行過程極為緩慢，因此我們需要手動重新實現加密邏輯，避免程式中不必要的延遲。
3.	重新實現加密邏輯：
-	我們可以透過 Python 等語言，將程式的邏輯用程式碼重現，快速計算出 flag。具體流程是：
	1.	提取出 unk_2060 和 unk_2168 的資料。
	2.	使用相同的 XOR 邏輯對資料進行運算，生成 flag。

---

### Python 解題腳本

Python 解題腳本：

```Python
import struct

data_2060 = b'' # 264 BYTES FROM 0x2060 
data_2168 = b'' # 4 BYTES FROM 0x2168 

if len(data_2060) != 264 or len(data_2168) != 4:
    print("Error: Please paste the correct data extracted from the binary.")
    exit()

v10_dwords = []
for i in range(0, 264, 4):
    dword = struct.unpack('<I', data_2060[i:i+4])[0]
    v10_dwords.append(dword)

last_dword = struct.unpack('<I', data_2168)[0]
v10_dwords.append(last_dword)

s = b"THJCCISSOGOODIMNOTTHEFLAG!!!"
v4 = 67 # Loop count
v5 = len(s) # 29

flag = ""

# Replicate the loop logic
for i in range(v4):
    s_char_val = s[i % v5]
    i_mod_256 = i # Since i < 256
    v6 = s_char_val ^ i_mod_256

    v10_dword = v10_dwords[i]
    low_byte_v10 = v10_dword & 0xFF
    final_byte = v6 ^ low_byte_v10

    flag += chr(final_byte)

print("Calculated Flag:")
print(flag)
```

---

## 結論

透過提取 ELF 檔案中的資料，並重現程式中的加密邏輯，我們成功跳過了程式中的 sleep() 延遲，並迅速計算出 flag。這個過程中的關鍵技術是理解偏移的概念，並正確地從二進位檔案中提取出需要的資料，然後重新實現加密邏輯以解出最終的結果。
