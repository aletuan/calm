# Product Vision, Target Users & Scope

## Vision
**Plug in (connect) → Discover → Visualize → Assess → Explain → Report.** Tạo một công cụ kiểm tra Guest Wi-Fi có thể dùng bởi kỹ sư thường, đồng thời đủ bằng chứng cho chuyên gia an ninh.

## Problem statements
1. SMB như nhà hàng/khách sạn/quán café có nhiều thiết bị IoT, CCTV, POS và Guest Wi-Fi nhưng hạn chế nhân lực bảo mật.
2. Kỹ sư được ủy quyền kết nối Guest Wi-Fi chưa biết có thể tiếp cận gì; không có quản trị router, SPAN/TAP hoặc agent.
3. Output của scanner tản mạn, khó hiểu, không được trình bày bằng topology/flow/evidence.
4. Các công cụ mã nguồn mở dùng định dạng và interface khác nhau, gây khó tổng hợp.

## Personas
- **Field assessor / IT technician:** muốn hoàn thành kiểm tra có kiểm soát, minh bạch, lặp lại được.
- **General software / DevOps engineer:** cần hiểu thuật ngữ, tại sao finding có ý nghĩa và độ tin cậy.
- **Security analyst:** cần evidence, confidence, raw artifacts, plugin validation.
- **Owner / managed service provider:** cần báo cáo dễ hiểu, đề xuất remediation, so sánh trước/sau.

## Deployment assumptions (locked baseline)
- Thiết bị kiểm tra: **một MacBook chạy macOS**, đã kết nối hợp lệ vào **Guest Wi-Fi** (managed mode).
- Không mặc định có password/quyền admin mạng, không cài agent vào thiết bị khác; không cần backend/cloud cho chức năng chính.
- Có thể cần cấp quyền hệ điều hành cho network diagnostics/packet capture; các phép test chủ động phải có authorization và allowlist.
- Thiết bị đối chứng thứ hai hoặc test endpoint là **tùy chọn** nhưng cần để chứng minh một số policy isolation.

## Goals
G1. Hiển thị mạng *theo những gì thực sự biết*, topology và provenance.
G2. Traffic charts và flow replay trong **phạm vi quan sát được**.
G3. Đánh giá Guest isolation và phơi lộ tài nguyên từ vị trí guest.
G4. Làm giàu findings bằng CVE/CWE/CPE/CVSS, KEV, EPSS khi có match đủ tin cậy.
G5. Giải thích đa tầng cho kỹ sư; dẫn nguồn bằng chứng và nói rõ giới hạn.
G6. Chuẩn mở; kết nối Nmap/PCAP/Nuclei/intel tools không khóa vendor.
G7. Hoạt động offline, bảo vệ quyền riêng tư và ảnh hưởng vận hành tối thiểu.

## Non-goals / anti-goals
- Không tự động pentest không giới hạn, brute force, gây mất kết nối, bypass xác thực, khai thác trên mạng sản xuất.
- Không khám phá đầy đủ toàn bộ Wi-Fi LAN/topology vật lý, thiết bị ngoài tầm với, hoặc traffic giữa mọi client.
- Không thay firewall, NAC, SIEM/SOC, EDR hay vulnerability manager toàn diện.
- Không xây một vulnerability scanner hoặc IDS engine mới từ đầu.
- Không coi đoán loại thiết bị/CVE từ banner là xác minh lỗ hổng.

## Differentiators
**Evidence-based Network Graph**, **Explain the Packet**, **Explain this Finding**, **Open Security Extension Platform**, **Confidence-aware Reporting**.

## Success metrics (targets to validate, not commitments)
- 100% findings có evidence link + status + confidence + test scope.
- 0 outbound active probes tới target ngoài allowlist trong kiểm thử tự động.
- ≥90% lượt nhập Nmap XML/PCAPNG fixtures qua compatibility tests thành công.
- ≥80% người thử nghiệm thuộc nhóm kỹ sư thường giải thích đúng ý nghĩa `reachable` vs `vulnerable` sau khi xem UI (usability study).
- Local baseline capture và report không yêu cầu tài khoản cloud.

## Product principles
Honest visibility; safety-by-default; learning-in-context; privacy/local-first; standards-first; deterministic findings with AI explanations; modular adapters.
