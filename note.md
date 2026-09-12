# Ghi chú tiến độ — EthicalQuoc

**Output tự động theo ngày + timestamp** — `Output/save_output.py` thêm `default_output_path(phase)`: nếu không truyền `-o`, tự tạo `results/<DDMMYYYY>/<phase>_<HHMMSS>.json` (tự tạo folder ngày nếu chưa có). `main.py` bỏ điều kiện `if args.output:` cũ (trước đây không truyền `-o` thì KHÔNG lưu gì cả) — giờ luôn lưu, chỉ khác tên/đường dẫn. Nếu user tự truyền `-o`, giữ nguyên đường dẫn đó (không tự ý nhét vào folder ngày). `save_output_file_type()` cũng tự `os.makedirs()` thư mục cha nếu thiếu, tránh crash khi path không tồn tại sẵn.

**Đã bỏ hết comment/docstring** trong 9 file theo yêu cầu (`ExploitabilityAnalysis.py`, `cleanfilter.py`, `payloadMutation.py`, `Utility/signatures.py`, `debug_pipeline.py`, `Replay/oracle_probe.py`, `Replay/replay_request.py`, `main.py`, `tool_config.py` — `normalize.py` đã làm ở lượt trước) — chỉ giữ lại code, không đổi logic. Verify bằng regression `test.har` + `result1.json` + bộ test gzip-wrapping (Ruby/.NET/NodeJS/Wrapper) — kết quả giống hệt trước.

## 0. File test benchmark chuẩn — `TestCase/comprehensive.har`

Đã xóa toàn bộ file test cũ (`test.har`, `example_multivalue_header.har`, `stress_test.har` + các JSON output tương ứng) — thay bằng **1 file benchmark chuẩn duy nhất**, giữ lại `results/result1.json`/`result2.json` (data lab thật, không đụng vào).

`TestCase/generate_comprehensive_har.py` — script sinh file HAR (giữ lại trong repo để tái tạo/mở rộng sau này, không phải blob JSON tĩnh khó sửa). Chạy `python TestCase/generate_comprehensive_har.py` để tạo lại `TestCase/comprehensive.har`.

`TestCase/comprehensive.har` — mô phỏng traffic thật của 1 web app (e-commerce + dashboard): **642 request** (620 nhiễu thực tế: browse/search/cart/analytics/static asset/WebSocket/IP-spoofing/JWT hợp lệ... + 22 payload nguy hiểm rải ngẫu nhiên, đủ 8 loại serialize + mọi edge case đã phát hiện trong session: multi-cookie đầu/giữa/cuối, gzip-wrap, short base64, Content-Disposition, Content-Type signal).

Cách dùng:
```
python main.py scan --har TestCase/comprehensive.har -o results/comprehensive_scan.json
python debug_pipeline.py -i results/comprehensive_scan.json --step 2   # PostFilter
python debug_pipeline.py -i results/comprehensive_scan.json --step 4   # Normalize
python debug_pipeline.py -i results/comprehensive_scan.json --step 5   # Fingerprint
```

**Fix độ thực tế của file benchmark** (user chỉ ra: HAR thật luôn có cookie+header+query+cache cùng lúc trên 1 request, file cũ mỗi malicious entry chỉ set đúng 1 dimension — dễ hơn thực tế, không lẫn payload vào noise thật của cùng request). Sửa `entry()` trong `generate_comprehensive_har.py`:
- Mọi request giờ luôn có baseline cookies (`_ga`/`cart_id`/`locale`) + full browser headers (Accept/UA/sec-fetch/...) merge với giá trị explicit truyền vào (explicit thắng theo từng key, các key baseline khác vẫn giữ).
- `cookies` dict và raw header `Cookie` giờ luôn khớp nhau (parse 2 chiều) — giống Chrome thật (cookie xuất hiện đồng thời ở `cookies[]` VÀ raw `Cookie` header, không phải chỉ 1 trong 2).
- Response giờ có `cookies`/`headers` (Content-Type, Server, X-Powered-By, Cache-Control), `cache.afterRequest` (eTag/hitCount, ~35% request), `content.text` — trước đây toàn để trống `{}`/`[]`.
- Verify: quét lại `comprehensive.har` (9859 vector, tăng từ noise dày hơn) + `debug_pipeline --step 5`, tất cả nhóm định dạng cũ (PHP/Java/Ruby/DotNet/Wrapper) vẫn detect đúng, các case biết-lỗi (`raw_body`, base64-padding) vẫn miss đúng như cũ — không regression. Regression `result1.json` (data lab thật) không đổi.

**Kết quả benchmark lần chạy đầu (2026-09-12), dùng cho RQ1/RQ2 — có số liệu thật:**
- Hiệu năng: 642 request → 5935 vector trong 0.94s; PostFilter 0.38s; Normalize 0.36s; Fingerprint 0.40s — không có vấn đề hiệu năng ở quy mô ~6000 vector.
- Giảm nhiễu: PostFilter giữ 39/5935 vector (99.34% loại bỏ).
- **False positive signal**: 27 header `Authorization` chứa JWT hợp lệ (benign) bị PostFilter giữ lại (do JWT trông giống base64 dài), nhưng `Fingerprint` đúng đắn phân loại `Unknown` — không sai lệch kết quả cuối, chỉ tốn thêm xử lý downstream.
- **False negative — định lượng chính xác 2 bug đã biết**: 6/22 payload thật (Java-gzip, Ruby-gzip, NodeJS-gzip-qua-header, Wrapper-gzip, YAML-gzip-qua-header, Pickle) bị mất — verify bằng số liệu: cả 6 đều có độ dài GỐC chia hết 4 (base64 hợp lệ) nhưng sau khi `.rstrip('=')` còn dư 2 hoặc 3 (fail check `%4==0`) — đúng 100% bug đã ghi bên dưới. Cộng 2/22 mất vì bug `raw_body` (NodeJS raw, YAML raw) = **8/22 (36%) tổng false negative từ 2 bug chưa fix**.

**`debug_pipeline.py`** (project root) — tool debug riêng, xem output tại đúng 1 bước trung gian thay vì phải chạy hết `analyze` rồi mới biết. Tái sử dụng y hệt class `main.py` dùng (không viết lại logic riêng, tránh lệch nhau như đã gặp với `TEST_COMMANDS`/signature trước đây):
```
python debug_pipeline.py -i results/scan.json --step 2   # PostFilter
python debug_pipeline.py -i results/scan.json --step 3   # + CleanFilter
python debug_pipeline.py -i results/scan.json --step 4   # + Normalize
python debug_pipeline.py -i results/scan.json --step 5   # + Fingerprint
python debug_pipeline.py -i results/scan.json --step 6   # + ExploitabilityAnalysis
python debug_pipeline.py -i results/scan.json --step 7   # + PayloadMutation
```
`-o <file>` để lưu output ra JSON thay vì chỉ in console.

**Đã phát hiện qua stress test/benchmark, CHƯA FIX (để dành theo từng bước):**
- [ ] `har_loader.py` tạo `location: "raw_body"` cho POST body dạng JSON/YAML/XML/raw text, nhưng `postfiltered.py`'s whitelist chỉ chấp nhận `"body"` (thiếu `"raw_body"`) → **mọi raw POST body bị loại bỏ hoàn toàn**, bất kể nội dung. Đo được: 2/22 payload benchmark mất vì lý do này.
- [ ] `postfiltered.py`'s generic base64-shape check (`_look_maybe_suspicious`) xóa padding `=` TRƯỚC rồi mới check `len % 4 == 0` — logic sai, vì base64 hợp lệ CÓ padding luôn chia hết 4 ở độ dài GỐC, xóa padding trước sẽ làm hầu hết base64 thật (có padding) fail check này. Đo được: 6/22 payload benchmark mất vì lý do này (Java/Ruby/NodeJS/Wrapper/YAML gzip-wrapped + Pickle).
- [x] `cleanfilter.py`'s `PREFIX_PATTERNS[2]` (`^[\w-]{1,32}\s*=\s*`) quá tham lam — base64 ngắn (≤33 ký tự, kết thúc đúng 1 dấu `=` padding) không khớp pattern cụ thể nào trước, bị hiểu nhầm toàn bộ là `tên_biến=` và xóa sạch thành chuỗi rỗng. Chỉ xảy ra khi value TRẦN (không phải multi-cookie header) có đúng 1 dấu `=` ở cuối và phần trước ≤32 ký tự word-char. **Đã fix**: `_clean()` nhận thêm `location`/`name`, chỉ chạy vòng lặp `PREFIX_PATTERNS` khi `location=="header"` và `name` là `"cookie"`/`"set-cookie"` (2 chỗ duy nhất value thật sự có thể chứa `tên=` bên trong) — các location khác value đã trần từ đầu (HAR tách sẵn tên/giá trị), giữ nguyên không bóc gì. Bonus không ngờ: case Content-Disposition (đã ghi nhận trước đây là hạn chế) giờ cũng detect đúng `PHP High` luôn, vì không còn bị `PREFIX_PATTERNS` can thiệp sai vào `form-data; name=...`. Verify bằng `comprehensive.har`: PHP tăng 4→5 (Unknown giảm 27→26), 2 bug còn lại (`raw_body`, base64-padding) không đổi (đúng dự kiến, khác file) — không regression
- [ ] `Analyze/normalize.py`'s `_generate_decodes()` dùng `.decode('utf-8', errors='ignore')` cho dữ liệu binary tùy ý (Java serialize, Pickle...) — byte không hợp lệ UTF-8 đứng một mình (ví dụ `\xac\xed` — 2 byte đầu magic Java) bị **xóa mất hẳn**, không phải hiển thị sai. Ảnh hưởng: Java payload sau khi giải nén gzip mất đúng 2 byte magic đầu, không detect được (`Unknown/Low`) dù PHP/Ruby/NodeJS/.NET/Wrapper cùng kịch bản đều decode đúng. Bug độc lập, có từ trước, chưa fix

## 1. Việc kỹ thuật còn thiếu

**`Analyze/normalize.py` — review + fix (session mới):**
- [x] `_is_serialized_payload()` chỉ có check Java/PHP/YAML/Pickle-keyword, thiếu Ruby/.NET/NodeJS/Wrapper → payload các loại này giải nén đúng qua gzip+base64 nhưng bị âm thầm vứt bỏ (không nhận ra là "có ý nghĩa"), trả về lại chuỗi gzip+base64 gốc chưa giải nén, `Fingerprint` không tự gzip-decompress được nên báo `Unknown/Low` — false negative đã verify bằng test thật. Fix: đổi sang gọi `signatures.looks_like_serialized()` (đã bao phủ đủ 8 loại)
- [x] `signatures.looks_like_serialized()` bản thân cũng thiếu check byte thô (chỉ có dạng chữ escape `\x04\x08` và base64 `BAh...`, không có byte điều khiển thật) — Ruby Marshal sau khi giải nén gzip ra byte thô không match được. Fix: thêm check `JAVA_MAGIC_BYTES + PICKLE_MAGIC_BYTES + RUBY_MAGIC_BYTES` trên `value.encode('utf-8', errors='ignore')`
- [x] `_serialized_score()` cũng chỉ có điểm cộng Java/PHP — candidate .NET đã giải nén đúng bị **hòa điểm** với chuỗi gzip+base64 chưa giải nén (cả 2 đều -3 vì cùng trông giống base64 thuần túy), tiebreaker chọn nhầm. Fix: thêm điểm cộng cho DOTNET_VIEWSTATE/DOTNET_PATTERNS/RUBY_PATTERNS/RUBY_MAGIC_BYTES/NODEJS_PATTERNS/WRAPPER_DANGEROUS (tái dùng `signatures.py`)
- Verify: cả 4 loại (Ruby/NodeJS/.NET/Wrapper) qua gzip+base64 giờ decode và detect đúng; PHP/Java-base64-đơn-lớp không regression (trừ bug byte-loss riêng ở trên, không liên quan 3 fix này)
- Đã bỏ hết comment trong file theo yêu cầu — logic giữ nguyên, verify lại bằng đúng bộ test trên

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
