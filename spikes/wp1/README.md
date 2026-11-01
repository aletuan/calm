# WP1 platform spike — runbook

Code spike **dùng xong bỏ**, không phải code product. Mục tiêu là trả lời 3 câu hỏi trước khi chốt ADR-002/ADR-008:

| Spike | Câu hỏi | Quyết định bị ảnh hưởng |
|---|---|---|
| S1 | Process nào đọc được SSID/BSSID qua CoreWLAN sau khi đã được cấp quyền Location? | Swift bridge chạy dạng sidecar CLI, helper `.app`, hay nằm trong process chính |
| S2 | Capture BPF không cần root thì cần những gì, và trải nghiệm cấp quyền thế nào? | Capture helper dùng group kiểu ChmodBPF hay `SMAppService` daemon |
| S3 | Developer ID + notarize với bundle có binary lồng bên trong có chạy trọn vẹn không? | Pipeline release |

**Yêu cầu:** MacBook thật (VM không có Wi-Fi), macOS 14+, Xcode CLT, Rust. Tốt nhất chạy S1 trong **một user account mới** để quyền Location/TCC cũ không làm sai kết quả.

**Quyền riêng tư:** script **che (mask) SSID/BSSID theo mặc định**. Chỉ cần biết giá trị *có hay không*, không cần giá trị thật. Thêm `RAW=1` chỉ khi muốn xem giá trị thật, và **đừng dán output RAW lại**.

Mọi lệnh chạy từ thư mục `spikes/wp1`:

```sh
cd spikes/wp1
```

## Bước 0 — Môi trường

```sh
scripts/00-env.sh
```
Nếu không thấy identity `Apple Development: …` thì tạo trong Xcode > Settings > Accounts > Manage Certificates. Không có identity này thì quyền TCC sẽ không giữ được qua mỗi lần rebuild.

## Bước 1 — S1: đọc SSID

1. Kiểm tra các lệnh có sẵn của macOS:
   ```sh
   scripts/s1-baseline-cli.sh
   ```
2. Build hai app bundle (`ProbeApp` thường và `ProbeAgent` ẩn khỏi Dock), mỗi bundle chứa `probe-cli` bên trong:
   ```sh
   scripts/s1-build-probe.sh
   ```
3. Chạy bộ test (Terminal CLI → ProbeApp → ProbeAgent):
   ```sh
   scripts/s1-run-probe.sh
   ```
   - Khi hộp thoại Location hiện ra: bấm **Allow**.
   - **Ghi lại bằng tay:** hộp thoại có hiện cho ProbeApp không? Có hiện cho ProbeAgent không? Câu chữ trong hộp thoại? App có tự thoát không, hay phải chờ 90 giây (`finish_reason=timeout-90s`)?
4. *(Không bắt buộc)* Test nhánh bị từ chối: vào System Settings > Privacy & Security > Location Services, xoá hoặc tắt ProbeApp, chạy lại bước 3 và bấm **Don't Allow**.

> Chạy app bằng `open` (script đã làm sẵn). Nếu gọi thẳng binary trong `Contents/MacOS` từ Terminal, macOS sẽ tính Terminal là app chịu trách nhiệm, và kết quả không còn đúng.

**Cách đọc `s1-summary.txt`:**

| variant | Ý nghĩa |
|---|---|
| `terminal-cli` | Kết quả đối chứng: process do Terminal chạy |
| `app-in-process` | App GUI tự đọc CoreWLAN sau khi được cấp quyền |
| `app-child-cli` | **Câu hỏi chính:** sidecar CLI con có được hưởng quyền của app cha không? |
| `agent-*` | Như trên nhưng app ẩn khỏi Dock (`LSUIElement`), gần với một helper |

## Bước 2 — S2: capture

```sh
STEP=unpriv scripts/s2-capture.sh        # dự kiến: lỗi permission
STEP=sudo   scripts/s2-capture.sh        # baseline khi chạy root
LOAD=1 STEP=sudo scripts/s2-capture.sh   # chạy root, có tải nền (~200 MB download)
scripts/s2-bpf-grant.sh                  # cấp quyền BPF tạm qua group (cần mật khẩu admin)
STEP=group  scripts/s2-capture.sh        # chạy không cần root sau khi cấp quyền
LOAD=1 STEP=group scripts/s2-capture.sh
scripts/s2-bpf-revoke.sh                 # BẮT BUỘC chạy để trả lại quyền mặc định
```
- **Ghi lại bằng tay:** sau `s2-bpf-grant.sh`, có phải **mở Terminal mới** thì `STEP=group` mới chạy được không?
- Mỗi lần chạy kéo dài 30 giây, snaplen 96 byte (chỉ header), không lưu và không in payload.
- Phương án B (`SMAppService` daemon + XPC) **chưa nằm trong đợt này**. Nó cần một container app đã ký và tốn công hơn nhiều. Mình sẽ viết sau khi có kết quả S1 và S3.

## Bước 3 — S3: notarize (khi đã có Developer ID)

Cần làm một lần:
- Có certificate **Developer ID Application** (tài khoản phải có vai trò Account Holder hoặc Admin).
- Tạo API key trên App Store Connect, rồi lưu thông tin notarize vào keychain:
  ```sh
  xcrun notarytool store-credentials calm-notary --key AuthKey_XXXX.p8 --key-id XXXX --issuer <issuer-uuid>
  ```

Sau đó chạy:
```sh
scripts/s3-notarize.sh
```
Thiếu điều kiện nào thì script dừng và ghi `MISSING: …`. Gặp trường hợp này cứ báo lại, không sao.

*(Không bắt buộc)* Copy `build/ProbeApp.app` đã staple sang một user account khác hoặc một máy Mac khác, mở bằng Finder, rồi ghi lại Gatekeeper có cảnh báo gì không.

## Gửi kết quả

```sh
scripts/collect.sh | pbcopy
```
Dán nội dung lại, kèm các ghi chú "ghi lại bằng tay" ở trên. Mình sẽ tổng hợp vào `docs/spikes/WP1-findings.md` và đề xuất cập nhật ADR.

## Dọn dẹp

- Chạy `scripts/s2-bpf-revoke.sh` nếu chưa chạy. Quyền `/dev/bpf*` cũng tự reset khi khởi động lại máy.
- Vào System Settings > Privacy & Security > Location Services và xoá các mục `ProbeApp` / `ProbeAgent`.
- Bundle ID của spike là `com.aletuan.calm.spike.*`, tách khỏi `com.aletuan.calm`, nên quyền cấp cho spike không lẫn vào app thật.
