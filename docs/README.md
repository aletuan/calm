# WiFi Security Auditor — Product & Engineering Documentation

**Status:** Draft for review | **Version:** 1.0 | **Date:** 2026-10-31 | **Language:** Vietnamese

## Tóm tắt
WiFi Security Auditor là ứng dụng desktop **macOS-first, local-first** để đánh giá an ninh Guest Wi-Fi từ góc nhìn một laptop đã kết nối hợp lệ, **không có quyền quản trị router/AP**. Sản phẩm kết hợp khám phá mạng có kiểm soát, **evidence-based topology**, phân tích **traffic mà laptop thực sự quan sát được**, vulnerability intelligence/validation qua extension mở, và lớp **giải thích khái niệm/kết luận** cho kỹ sư thông thường.

> **Giới hạn bất biến:** Không hứa hẹn nhìn thấy toàn bộ mạng, mọi VLAN, mọi client hoặc toàn bộ Wi-Fi traffic chỉ bằng một laptop Guest Wi-Fi. Các kết quả chưa đủ bằng chứng phải hiển thị `Inconclusive`/`Not tested`.

## Document map

| Tài liệu | Mục đích |
|---|---|
| [Vision & scope](product/01-vision-and-scope.md) | Định vị, personas, phạm vi và giả định |
| [PRD](product/02-product-requirements.md) | Yêu cầu sản phẩm, NFR và acceptance |
| [Feature specs](product/03-feature-specifications.md) | Chức năng chi tiết và UX behavior |
| [User journeys](product/04-user-journeys.md) | Workflow, wireframe logic, use cases |
| [Calm Technical UI guidelines](design/01-calm-technical-ui-guidelines.md) | Design tokens, density, progressive disclosure, Topology V2 interaction contract |
| [System architecture](architecture/01-system-architecture.md) | Components, deployment, runtime flows |
| [Data & evidence model](architecture/02-data-and-evidence-model.md) | Entity, schema, semantics, provenance |
| [Extension interoperability](architecture/03-extension-and-standards.md) | SDK, standards, adapters, formats |
| [Explainability](architecture/04-explainability-engine.md) | Kiến thức nền, AI grounding, UX explanation |
| [ADRs](architecture/adr/README.md) | Quyết định kỹ thuật và trade-off |
| [Security testing methodology](security/01-assessment-methodology.md) | Rule of engagement, test levels, safety |
| [Security & privacy](security/02-product-security-and-privacy.md) | Threat model sản phẩm, bảo vệ dữ liệu |
| [Engineering plan](engineering/01-implementation-plan.md) | Stack, repo, interfaces, testing |
| [Roadmap](delivery/01-roadmap-and-milestones.md) | Giai đoạn, ưu tiên, dependency, exit criteria |
| [Risks & open questions](delivery/02-risks-and-open-questions.md) | Rủi ro, rào cản, quyết định còn mở |
| [Acceptance & test plan](delivery/03-acceptance-and-test-plan.md) | Test matrix, acceptance, DoD |
| [Glossary](reference/glossary.md) | Từ điển thuật ngữ |
| [Standards & sources](reference/standards-and-sources.md) | Nguồn kỹ thuật, trạng thái áp dụng |
| [Sample schemas](examples/) | Manifest, findings, assessment policy |

## Reading paths
- **Product/PM:** vision → PRD → feature specs → roadmap → risks.
- **Engineering:** architecture → ADRs → data model → extension contracts → implementation.
- **Security reviewer:** methodology → security/privacy → acceptance → risks.
- **UX/AI:** feature specs → journeys → Calm Technical UI guidelines → explainability → evidence model.

## Requirements language
`MUST` = bắt buộc; `SHOULD` = nên; `MAY` = tùy chọn. Priorities: `P0` MVP, `P1` v1.x, `P2` future. Tài liệu là **thiết kế đề xuất**, không khẳng định các tích hợp/khả năng đã được triển khai. Tất cả ví dụ dữ liệu trong `examples` là giả lập.
