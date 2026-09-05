# Ghi chú tiến độ — EthicalQuoc

## 0. File test cố định — `TestCase/test.har`

`TestCase/test.har` là fixture HAR cố định, 13 request phủ đủ 8 loại serialize + case multi-cookie target đứng đầu/cuối + 1 case benign (check false positive) + 1 case IP-spoofing header (check đã bỏ đúng). Dùng để test end-to-end mỗi khi sửa 1 bước trong pipeline, thay vì chỉ test hàm lẻ.

`TestCase/example_multivalue_header.har` — file minh họa RIÊNG (không phải bộ regression chính), 4 case: Cookie target đứng đầu/giữa/cuối + Content-Disposition (RFC 6266/7578, cùng cấu trúc `"; "`-separated name=value như Cookie nhưng ít liên quan thực tế hơn nhiều vì multipart field value đã có sẵn sạch qua `postData.params`).

Cách dùng:
```
python main.py scan --har TestCase/test.har -o results/test_scan.json
python main.py analyze -i results/test_scan.json -o results/test_analyze.json
```
`results/test_scan.json`/`results/test_analyze.json` giữ lại làm baseline so sánh — không xóa như file test tạm khác.

**`debug_pipeline.py`** (project root, file mới) — tool debug riêng, xem output tại đúng 1 bước trung gian thay vì phải chạy hết `analyze` rồi mới biết. Tái sử dụng y hệt class `main.py` dùng (không viết lại logic riêng, tránh lệch nhau như đã gặp với `TEST_COMMANDS`/signature trước đây):
```
python debug_pipeline.py -i results/test_scan.json --step 2   # PostFilter
python debug_pipeline.py -i results/test_scan.json --step 3   # + CleanFilter
python debug_pipeline.py -i results/test_scan.json --step 4   # + Normalize
python debug_pipeline.py -i results/test_scan.json --step 5   # + Fingerprint
python debug_pipeline.py -i results/test_scan.json --step 6   # + ExploitabilityAnalysis
python debug_pipeline.py -i results/test_scan.json --step 7   # + PayloadMutation
```
`-o <file>` để lưu output ra JSON thay vì chỉ in console.

**Đã phát hiện qua lần chạy đầu tiên (test.har), CHƯA FIX (để dành theo từng bước):**
- [ ] `har_loader.py` tạo `location: "raw_body"` cho POST body dạng JSON/YAML/XML/raw text, nhưng `postfiltered.py`'s whitelist chỉ chấp nhận `"body"` (thiếu `"raw_body"`) → **mọi raw POST body bị loại bỏ hoàn toàn**, bất kể nội dung. Ảnh hưởng: NodeJS/YAML/raw Java body test case đều mất vì lý do này.
- [ ] `postfiltered.py`'s generic base64-shape check (`_look_maybe_suspicious`) xóa padding `=` TRƯỚC rồi mới check `len % 4 == 0` — logic sai, vì base64 hợp lệ CÓ padding luôn chia hết 4 ở độ dài GỐC, xóa padding trước sẽ làm hầu hết base64 thật (có padding) fail check này. Ảnh hưởng: Pickle base64 (không có signature riêng, dựa vào check chung này) bị loại oan.

## 1. Việc kỹ thuật còn thiếu

- [ ] Unit test chính thức (hiện chỉ có `Analyze/test.py` — 6 dòng scratch, không phải test suite)
- [x] Oracle probe — đã code cho PHP (length-corruption technique), chạy trước khi replay toàn bộ mutation batch, chỉ bổ sung bằng chứng chứ không gate/skip. Còn thiếu cho Java/Pickle/YAML/.NET/NodeJS/Ruby/Wrapper
- [x] OOB "nhẹ" — `config.json`'s `oob_domain` (hoặc `ETHICALQUOC_OOB_DOMAIN`) nhúng canary domain thật vào URLDNS + blind-SSRF payload. Vẫn phải tự check interaction log thủ công, không tự động poll API Interactsh/Burp Collaborator
- [ ] `.NET`/`Wrapper` mutation mới code, chưa test trên lab thật (chỉ test bằng mock, chưa có `ysoserial.net`/`Gopherus` cài)
- [ ] `scan --url` (Playwright) chưa từng chạy thử thật trong suốt session
- [ ] `report` command mới có format JSON, PDF/HTML còn là placeholder
- [x] `Gopherus` — đã clone mã nguồn thật vào `Analyze/third_tool/gopherus/`. **Lưu ý: viết cho Python 2, chạy Python 3 sẽ SyntaxError.** Đã thêm `_find_python2()` tự dò `python2`/`py -2`/`C:\Python27\python.exe`, fallback về payload Redis INFO benign nếu không có Python 2. Cần tự cài Python 2.7 nếu muốn dùng đầy đủ (xem README)
- [ ] `ysoserial.net` — vẫn chưa vendor, cần tự tải file `.exe` từ https://github.com/pwntester/ysoserial.net/releases và copy vào `Analyze/third_tool/dotnet/ysoserial.exe` (không tự động tải vì là binary, cần bạn tự verify an toàn)
- [x] **Signature bị trùng giữa `postfiltered.py` và `finderprint.py`** — đã gom vào `Utility/signatures.py` (module mới, single source of truth cho mọi list/pattern: PHP/Java/Pickle/YAML/.NET/NodeJS/Ruby/Wrapper + hàm `is_nodejs_prototype_pollution()` cho logic constructor/prototype dùng chung, + hàm `looks_like_serialized()` dùng chung giữa PostFilter và CleanFilter). Ban đầu tạo ở `Analyze/signatures.py`, sau chuyển sang `Utility/signatures.py` (folder mới, tách utility ra khỏi Analyze). `finderprint.py` alias class attribute về `signatures.XXX`; `postfiltered.py`/`cleanfilter.py` import trực tiếp dùng. Bonus: đổi luôn regex PHP tự viết (`[Oaidsb]:\d+:` có `(?i)` quá rộng) sang dùng `signatures.PHP_STRONG`/`PHP_WEAK` chính xác hơn

## 2. Bug đã fix trong session này (để tham khảo, không cần làm lại)

- `analyze --output` từng luôn ghi placeholder rỗng, bỏ hết kết quả thật
- `PayloadMutation` nhận nhầm object → mutation PHP không bao giờ chạy
- Crash Unicode (`→`) trên console Windows mặc định
- Fingerprint `type: "Ruby"` bị thiếu trong `ExploitAnalyze.dispatch` → luôn báo "Low/not exploitable"
- Sai tên probe `"urldns"` vs `"urldns_probe"` → mất payload URLDNS đáng lẽ mạnh nhất
- `PHPGGC_PATH` trỏ vào thư mục thay vì file script `phpggc/phpggc` → phpggc **chưa bao giờ chạy được**, kể cả trước khi tôi sửa gì
- `tool_config.py` crash khi `config.json` có `"tools": null`
- `postfiltered.py` dùng `and` thay vì `or` → crash khi `value` là `None`
- `ReplayRequest` crash `ValueError` khi payload nhị phân (Pickle) chứa `\r`/`\n` trong header/cookie
- Method bị báo sai (GET thay vì POST thực tế) khi payload ở body/form_body
- `Analyze/third_tool/phpggc` từng là gitlink hỏng (submodule không có `.gitmodules`) → thư mục rỗng mỗi lần clone mới — đã fix bằng cách vendor lại thật
- `_run_ysoserialnet` thiếu bắt `OSError`/`PermissionError` → có thể crash cả vòng lặp `analyze`
- Method bị báo sai lần 2 trong `ReplayRequest` + code trùng lặp `TEST_COMMANDS` × 6 chỗ — đã dọn về 1 nguồn
- `postfiltered.py` — scan toàn diện, fix 3 vấn đề: bỏ `import os`/`import json` chết; `"sec-websocket-*"` không bao giờ match (code kiểm tra exact-match, không hỗ trợ wildcard) → thay bằng 5 tên header WebSocket thật; crash `AttributeError` khi `name` là `None` (giống bug `value` trước đó nhưng ở field khác)
- `postfiltered.py` — `Suspicious_header` trước đây gộp cả header IP-spoofing (`x-forwarded-for`, `x-real-ip`, `client-ip`, `true-client-ip`) không liên quan deserialization, giữ vô điều kiện gây nhiễu → đã bỏ, chỉ giữ nhóm auth/token thật sự liên quan
- `postfiltered.py` — `content-type` từng bị chặn vô điều kiện trong `Ignore_header_name`, khiến tool không bao giờ phát hiện được `Content-Type: application/x-java-serialized-object` (tín hiệu mạnh nhất cho Java deserialization qua Spring HttpInvoker/JBoss remoting) → đã bỏ khỏi ignore list + thêm signature riêng
- `postfiltered.py` — `_look_maybe_suspicious()` có check riêng cho Java/PHP nhưng KHÔNG có cho Pickle/.NET/Ruby/NodeJS (chỉ sống sót nhờ heuristic chung, không chắc chắn) → đã thêm check riêng cho cả 4 loại, đồng bộ với `finderprint.py`. Verify bằng test thật: payload `constructor.prototype.isAdmin=true` (NodeJS prototype pollution) trước đây bị loại oan dù `ExploitabilityAnalysis` đã có logic nhận diện đúng nó — giờ đã fix
- `cleanfilter.py` — header `Cookie` chứa nhiều cookie ghép (`session=<payload>; other=abc; tracking=xyz`) chỉ bị cắt phần đầu (`session=`), phần đuôi (cookie khác) dính nguyên vào `cleaned_value`, sau đó `normalize.py` cố decode luôn phần rác này ra byte nhị phân lẫn vào payload thật. Fix v1 (sáng): sau khi strip prefix, cắt tại dấu `"; "` đầu tiên. An toàn cho PHP vì PHP serialize dùng `;` không có dấu cách theo sau (`b:0;}` chứ không phải `b:0; }`)
- `cleanfilter.py` — Fix v1 chỉ đúng khi cookie mục tiêu đứng ĐẦU chuỗi gộp; nếu đứng giữa/cuối (`tracking=xyz; session=<payload>`), fix v1 lấy nhầm cookie đầu tiên → **false negative im lặng** (Fingerprint báo `Unknown/Low`, mất hoàn toàn payload thật, không có dấu hiệu báo lỗi). Nghiêm trọng hơn khi HAR không có mảng `cookies[]` sạch đi kèm (nguồn không phải Chrome, hoặc `scan --url` qua Playwright — không có mảng cookie riêng). Cùng gốc rễ với Content-Disposition (`form-data; name=...; filename=...` — cùng cấu trúc `"; "`-separated). Fix v2: chuyển `_look_maybe_suspicious()` từ `postfiltered.py` sang `signatures.looks_like_serialized()` dùng chung; `cleanfilter._clean()` giờ tách theo `"; "` thành từng đoạn, CHẤM ĐIỂM từng đoạn bằng hàm chung đó, giữ đoạn nào thật sự giống payload — không còn giả định "luôn ở vị trí đầu". Verify bằng 4 case (`example_multivalue_header.har`): Cookie đầu/giữa/cuối đều ra đúng `PHP High` y hệt nhau; Content-Disposition cải thiện đáng kể (không còn rác `form-data`) nhưng chưa auto-decode hoàn toàn (dính đuôi `.txt` từ `filename=`) — chấp nhận vì vector này ít liên quan thực tế
- `cleanfilter.py` — bug "2 lớp wrap chồng" (`Cookie: session=<payload>`) trước đây không fix được vì vòng lặp `PREFIX_PATTERNS` chỉ chạy 1 lượt: pattern `session=` bị kiểm tra và bỏ qua TRƯỚC khi `Cookie:` được strip, nên khi `session=` lộ ra không ai quay lại strip nữa. Fix: đổi `for` (1 lượt) thành `while changed` (lặp lại đến khi 1 lượt đầy đủ không còn thay đổi gì) — tự dừng đảm bảo vì mỗi lần strip thành công luôn làm ngắn chuỗi đi. Verify: case 2 lớp VÀ 3 lớp (`Set-Cookie: Cookie: session=`) đều bóc hết đúng, không lặp vô hạn, không regression với các test case cũ

## 3. Việc học thuật — quan trọng hơn code lúc này

- [ ] **Dữ liệu định lượng** — hiện chỉ có 1 ví dụ (PHP/PortSwigger). Cần chạy tool trên nhiều lab khác nhau (Java, .NET ViewState có sẵn trên PortSwigger; Pickle/YAML có thể cần tự dựng lab), ghi bảng: format × detected đúng/sai × confidence × thời gian
- [ ] **False positive rate** — chạy tool trên traffic KHÔNG có lỗ hổng, đo tỷ lệ báo động giả (hội đồng gần như chắc chắn hỏi câu này)
- [ ] **So sánh định lượng với baseline** — đo thời gian phát hiện thủ công (ysoserial/phpggc tay) vs bằng tool, thay vì chỉ so sánh tính năng (Table 1 hiện tại)
- [ ] **Literature Review thiếu paper học thuật** — hiện chỉ cite tool (ysoserial, phpggc, OWASP, PortSwigger docs), thiếu paper IEEE/ACM/USENIX về static/dynamic analysis cho deserialization
- [ ] **Threats to Validity** — chưa có mục nêu rõ giới hạn phương pháp luận (chỉ test PortSwigger — môi trường dễ phát hiện, không đại diện thật; static signature dễ false positive vì suy đoán không xác nhận runtime)
- [ ] **Contribution Statement** — chưa có đoạn tóm tắt rõ ràng đóng góp chính, để hội đồng dễ so khớp với RQ

## 4. Ưu tiên nếu thời gian gấp

1. Viết **Threats to Validity** + **Contribution Statement** (không cần code, tác động điểm cao)
2. Chạy tool trên 2–3 lab khác nhau, ghi bảng số liệu thật cho RQ1/RQ2
3. Thêm vài citation học thuật thật vào Literature Review
4. ~~Oracle probe + OOB integration~~ — đã làm phần PHP + OOB nhẹ; mở rộng sang các loại còn lại nếu còn thời gian
