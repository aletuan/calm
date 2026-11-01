# Glossary for General Engineers

| Term | Giải thích ngắn | Lưu ý khi kiểm tra |
|---|---|---|
| WLAN | Mạng cục bộ không dây | Kết nối qua AP không bảo đảm nhìn toàn mạng |
| SSID | Tên mạng Wi-Fi | Nhiều AP/BSSID có thể chia sẻ một SSID |
| BSSID | Định danh radio/AP ở mức kết nối | Không luôn ánh xạ 1:1 tới router |
| AP | Điểm truy cập không dây | Có thể chỉ bridge thay vì định tuyến |
| Default Gateway | Next hop cho đường đi mặc định | Có thể khác AP |
| DHCP | Cấp IP và các tham số mạng tự động | Cấp IP không đồng nghĩa có quyền truy cập khác |
| DNS | Hệ thống phân giải tên miền | Có thể có resolver nội bộ/ngoài |
| Subnet | Nhóm địa chỉ theo prefix | Không chứng minh VLAN vật lý |
| VLAN | Phân đoạn mạng logic L2 | Không nhất thiết thấy ID từ client |
| ACL | Quy tắc cho phép/chặn traffic | Đánh giá bằng endpoint và chính sách đã được cấp |
| Client isolation | Hạn chế liên lạc giữa các client | Cần client/endpoint đối chứng để chứng minh |
| NAT | Dịch địa chỉ mạng | Che đi nhiều host sau cùng địa chỉ public |
| TCP handshake | SYN, SYN-ACK, ACK thiết lập TCP | Không chứng minh xác thực ứng dụng |
| TLS | Bảo mật truyền tải | Packet capture thường không thấy payload plaintext |
| PCAPNG | Định dạng lưu packet capture | Có thể chứa dữ liệu nhạy cảm |
| Flow | Tóm tắt trao đổi giữa endpoints | Không phải tất cả gói tin của mạng |
| CVE | ID lỗ hổng công khai | Không phải finding xác minh trên mạng của bạn |
| CWE | Nhóm điểm yếu phần mềm | Phân loại nguyên nhân |
| CPE | Tên sản phẩm/phiên bản chuẩn hóa | Fingerprinting có thể sai |
| CVSS | Chỉ số mức nghiêm trọng kỹ thuật | Không phải xác suất sẽ bị tấn công |
| KEV | Danh mục lỗ hổng đã bị khai thác thực tế | Không chứng minh tài sản tại chỗ bị ảnh hưởng |
| EPSS | Xác suất dự báo khai thác CVE | Không phải severity hay certainty |
| SARIF | Chuẩn kết quả phân tích | Chủ yếu cho findings, không thay PCAP |
| STIX/TAXII | Biểu diễn và vận chuyển threat intelligence | Không phải full topology API |
| MCP | Protocol để AI tương tác với tools/resources | Không phải OS sandbox |
| Confidence | Độ chắc chắn của bằng chứng | Tách khỏi mức severity |
| Inconclusive | Chưa đủ chứng cứ kết luận | Không đồng nghĩa Pass |
| Vantage point | Vị trí/quyền của nơi quan sát | Một Guest Wi-Fi laptop có blind spots lớn |
