---
title: Teslacrypt Ransomware
date: 2025-09-25 07:00:00 +0700
categories: [Malware, Ransomware]
tags: [teslacrypt, unpacking, analysis]
description: Phân tích mẫu ransomware Teslacrypt - phát hiện packing, dump payload, nhận diện thành phần chính qua debug và kiểm tra PE.
media_subpath: /resources/demo1_ransomware
---

## 📌 1. Kiểm tra thông tin cơ bản

- **Tên file:** `demo1_ransomware.bin` (Teslacrypt ransomware)
- **MD5:** `9ce01dfbf25dfea778e57d8274675d6f`

### 🔸 Kết quả VirusTotal
`Trojan.Teslacrypt ransomware`
![Kết quả VirusTotal](Pasted%20image%2020251003070446.png)

### 🔸 ExeinfoPE
- Loại file: 32-bit, GUI
![ExeinfoPE](Pasted%20image%2020251003070713.png)

### 🔸 DIE (Detect It Easy)
- **Heuristics:** Packer detected
- Entropy `.data` section = **7.629** → dấu hiệu bị pack
![DIE - Heuristics](Pasted%20image%2020251003070801.png)

### 🔸 PEstudio
![Pestudio - tổng quan](Pasted%20image%2020251003071323.png)
![Pestudio - sections](Pasted%20image%2020251003072403.png)

**Nhận xét nhanh:**
- Có section lạ `para`
- `.data` có quyền ghi + entropy cao → khả năng unpack tại chỗ
- `code`, `crt`, `erloc` section đều có entropy cao, không chuẩn
- **Indicators** có dòng: `imports > flag > count,1,1`
- Gọi API `GlobalMemoryStatus` (KERNEL32.dll) → thu thập thông tin bộ nhớ

![Pestudio - imports](Pasted%20image%2020251003072240.png)

---

## 🧭 2. Debug bằng x64dbg

Dựa vào các dấu hiệu packer, ta **đặt breakpoint tại `VirtualAlloc`**. API này được gọi 2 lần:

### 🟡 Lần 1
- Địa chỉ cấp phát: `00A40000`
- Size: `0004A000`
- Protection: `-RW--`
- Dữ liệu được ghi vào vùng nhớ:

![Dump lần 1](Pasted%20image%2020251003074717.png)

---

### 🟡 Lần 2
- Địa chỉ cấp phát: `00A90000`
- Size: `00085000`
- Protection: `ERW--`

![Dump lần 2](Pasted%20image%2020251003075109.png)

Quan sát thấy phần đầu có dạng giống PE, nhưng không đầy đủ → dump **vùng nhớ lần 1** để kiểm tra.

---

## 🔍 3. Phát hiện cấu trúc PE ẩn

Sau khi kiểm tra vùng nhớ dump, phát hiện **2 vị trí nghi ngờ chứa PE header**:

```
00006AFB 4D5A MZ 000000B0 ( PE )
Exe PE detected at offset :00006AFB - section : ???
0000940F 4D5A MZ 00000100 ( PE )
Exe PE detected at offset :0000940F - section : ???
```


Dump 2 vùng này → thu được:

- `demo1_ransomware_dump1.bin`

![Dump1](Pasted%20image%2020251003080559.png)

- `demo1_ransomware_dump2.bin`

![Dump2](Pasted%20image%2020251003080807.png)

---

## 🧠 4. Phân tích payload dump

- **Dump1**: không có import table → loại
- **Dump2**: có đầy đủ thông tin PE → **chọn dump2**

**MD5:** `59cd9a688eddff21cbc9dc31b4f77b35`

![Thông tin PE Dump2](Pasted%20image%2020251003081019.png)

Khi phân tích trên VirusTotal hash mới này, có thể thấy:

- Nhiều chuỗi command & control, URL, lệnh tải về (download)
- Đặc trưng của payload ransomware Teslacrypt

![VirusTotal payload](Pasted%20image%2020251003081551.png)

---

## 📝 5. Kết luận

- Mẫu `demo1_ransomware.bin` **được pack** (entropy cao, gọi VirtualAlloc để giải nén).
- Qua debug, đã **dump thành công payload** tại lần cấp phát thứ nhất.
- Payload dump (`dump2`) chứa đầy đủ thông tin hoạt động của Teslacrypt ransomware.
- Dừng phân tích tại đây để tránh thực thi mã độc thực tế trên máy.

---

## 📎 Ghi chú

- Đây là **kỹ thuật unpack thủ công** cơ bản: theo dõi `VirtualAlloc`, dump memory, tìm PE header.
- Dùng tốt cho các mẫu ransomware cổ điển như Teslacrypt.
- Bước tiếp theo (nếu môi trường sandbox an toàn): phân tích hành vi mạng, giải mã routine mã hóa file, v.v.

---
