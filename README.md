# SOC – Security Operations Center Demo

## Giới thiệu / Overview

Đây là kho lưu trữ demo dùng cho mục đích kiểm thử SOC (Security Operations Center), bao gồm các tệp giả lập (fake) để thử nghiệm quy trình phát hiện mối đe dọa, giám sát tính toàn vẹn tệp (FIM) và kiểm tra chỉ số xâm phạm (IOC).

This repository is a demo used for SOC testing purposes. It contains simulated (fake) files to test threat detection workflows, File Integrity Monitoring (FIM), and Indicator of Compromise (IOC) checks.

---

## Cấu trúc tệp / File Structure

| Tệp / File       | Mô tả / Description                                                          |
|------------------|-------------------------------------------------------------------------------|
| `malware-demo.exe` | Tải trọng giả lập (không độc hại) để demo SOC / Fake (harmless) payload for SOC demo |
| `malware.txt`      | Tệp văn bản dùng để kích hoạt cảnh báo FIM / Text file used to trigger FIM alerts |
| `demo-malware.txt` | Tệp kiểm thử IOC / IOC test file                                             |

---

## Cách sử dụng / Usage

1. **Kiểm thử FIM (File Integrity Monitoring):** Chỉnh sửa nội dung `malware.txt` hoặc `demo-malware.txt` để kiểm tra xem hệ thống giám sát có phát hiện thay đổi không.  
   *Edit `malware.txt` or `demo-malware.txt` to verify that your FIM system detects the change.*

2. **Kiểm thử IOC:** Dùng hash hoặc tên của `malware-demo.exe` trong quy trình tìm kiếm IOC của bạn.  
   *Use the hash or name of `malware-demo.exe` in your IOC search workflow.*

3. **Demo SOC:** Sử dụng kho này trong môi trường lab để huấn luyện phân tích viên bảo mật nhận diện và phản hồi cảnh báo.  
   *Use this repo in a lab environment to train security analysts to identify and respond to alerts.*

---

## Lưu ý / Disclaimer

> ⚠️ **Tất cả các tệp trong kho này đều là giả và không gây hại.** Chúng chỉ được tạo ra cho mục đích học tập và kiểm thử SOC trong môi trường kiểm soát.  
> ⚠️ **All files in this repository are fake and harmless.** They are created solely for educational and SOC testing purposes in a controlled environment.
