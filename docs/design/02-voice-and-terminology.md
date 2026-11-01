# Calm: voice, text patterns and terminology

**Status:** Accepted, 2026-11-01. Batch 2 (forms and errors) applied the same day. The mechanical rules are enforced by `apps/desktop/src/i18n/i18n.test.ts` ("voice rules").

## Voice

Calm speaks like a calm network-security engineer explaining things to a capable colleague who is not a network specialist. The product name is a promise: no alarm, no exaggeration.

When these four traits conflict, the earlier one wins:

1. **Precise.** Say only what the evidence supports. Name what is unknown. Use real numbers and units.
2. **Transparent.** Every conclusion carries its limit ("shows…", "does not show…"). Say what Calm will do before it does it.
3. **Helpful.** Always give a next step. Explain a term in plain words the first time it appears.
4. **Calm.**
   - Keep sentences short.
   - No exclamation marks.
   - No scary words ("critical", "fatal", "attack") unless they are literally true.
   - No jokes, no emoji.

## Tone by situation

| Situation | Tone | Do | Don't |
|---|---|---|---|
| First use, empty screen | Guiding | Why it is empty, what to do, one button | Future features, build names |
| Labels, buttons, columns | Neutral, minimal | Noun or verb, 1–4 words | Explanations inside labels |
| Input not accepted | Neutral | Say the accepted value, next to the field | "Invalid", blame |
| System error | Factual, reassuring | What happened, whether data is safe, what to do | Guessing causes, raw codes first |
| Safety warning (scope, outside subnet, stop) | Direct, short | Concrete risk, safe choice most prominent | Softening, risky default |
| Irreversible action | Direct | State the consequence; button names the action | "OK" / "Yes" |
| Fail / warning finding | Serious, not alarmed | Saw → means → does not show → do | "Your network is compromised" |
| Pass / not tested / inconclusive | Careful | State exactly what was tested | "Safe", "no problems" |
| Done (saved, finished) | Brief | One line plus where to look | Congratulations |

## Writing rules (EN and VI)

1. **Address.**
   - EN: "you"; Calm refers to itself as "Calm", never "we".
   - VI: "bạn", or no pronoun when the sentence is still clear. Never "anh" or "chị".
2. **First person** appears only in the user's own attestations: `scope.confirm` and `assess.receiverConfirm` ("I have…" / "Tôi có…").
3. **Sentence case everywhere.** Capitalize only proper names (Wi-Fi, macOS, Keychain, Calm), check IDs (S01), acronyms and screen names.
4. **Punctuation.**
   - Labels, buttons, headings and column names: no final period, no colon after a label.
   - Full sentences end with a period.
   - "…" appears only on a button that opens another step.
   - No exclamation marks. Use a period instead of a dash.
5. **Length.**
   - Buttons and labels: 1–4 words.
   - Sentences: under 20 words.
   - Screen descriptions: at most 2 sentences.
   - Tooltips: under 120 characters.
   - VI runs longer by nature. Where width is fixed (buttons, field labels, column headers), VI stays within 1.3× EN, or 6 characters more on very short labels. Running text has no length ratio.
6. **One idea per sentence.** Never hide something important in parentheses.
7. **Numbers.**
   - Use numerals, with a space before the unit (4 ms).
   - Ranges use an en dash (1–10).
   - VI uses a decimal comma (0,5 giây).
8. **Avoid.**
   - EN: invalid, failed, please, simply, obviously, fatal, and internal build words (skeleton, alpha, stub, L0).
   - VI: vui lòng, không hợp lệ, thất bại.
9. **Certainty matches the evidence.** "Calm saw" (observed), "likely" (inferred), "not checked" (unverified). Never claim "safe" or "secure" outright.
10. **One spelling.** VI uses the older tone placement throughout: uỷ, hoá, khoá, xoá (not ủy, hóa, khóa, xóa).
11. **Data stays data.**
    - IPs, ports, commands and check IDs are in monospace.
    - Data values (SSID, hostnames) are never translated.

## Patterns

| Kind | Shape |
|---|---|
| Screen description | What the screen helps you do, plus one important limit. Max 2 sentences |
| Field hint | One sentence: the accepted value, or why the field exists |
| Primary button | Verb + object ("Approve scope", "Run checks") |
| Irreversible action | "Revoke…" opens a confirmation that states the consequence, with "[Revoke now] [Cancel]" |
| Empty state | Title stating the situation, 1–2 sentences with the reason and next step, one button |
| Input error | The value that is accepted, as a full sentence ("Enter ports from 1 to 65535."). Several errors are listed one per line, under the buttons |
| System error | Title: "Calm could not…". Body: the cause if certain, whether data is safe, what to do. A raw code or size goes on a separate "Detail" line, never first |
| Finding detail | What Calm saw, What this shows, What this does not show, What to do, Evidence, Method and limits |

## Terminology

**Decision (2026-11-01):** Vietnamese keeps the English product and security terms below, so the UI, docs and reports use the same words. Judgments and everyday words are translated.

| Concept | EN and VI (kept in English) | Explain on first use (VI) |
|---|---|---|
| Container for one assessment | session | "Session giữ những gì bạn lưu từ một lần đánh giá." |
| Saved copy | snapshot | — |
| Permission to test | scope | "Phạm vi chủ mạng cho phép kiểm tra: địa chỉ, cổng, thời hạn." |
| Device in the scope | target | — |
| A named test (S01…) | check | — |
| One TCP attempt | probe | "Một lần thử kết nối rồi đóng ngay, không gửi dữ liệu." |
| Result of a check | finding | — |
| Recording traffic / one connection | capture · flow · traffic | — |
| Screen names | Sessions · Network · Topology · Traffic · Assessment · Findings · Extensions · Reports | Menu stays English in both languages. Settings is "Cài đặt" |

| Concept | EN | VI (translated) |
|---|---|---|
| Certainty | observed · validated · inferred · unverified | quan sát được · đã xác thực · suy luận · chưa xác minh |
| Finding status | pass · fail · warning · inconclusive · not tested | đạt · không đạt · cảnh báo · chưa kết luận · chưa kiểm tra |
| Severity · confidence | severity · confidence | mức độ · độ tin cậy |
| Stop control | Stop everything | Dừng tất cả |
| Second device | receiver | máy nhận |
| Evidence | evidence | bằng chứng |
| Owner's written permission, by id | authorization reference | mã uỷ quyền |
| Inferred | inferred | suy luận (never "suy ra") |

The research and the before/after examples behind these rules live in the shared proposal "Calm — Giọng văn và cách viết label, guidance".
