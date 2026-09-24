# 历史来源索引

D01–D16、C01–C32 的路径均相对本地 `reference/winmdm20260220-develop/`，已核对文件存在。快照由 Git 忽略，恢复方式见 [历史参考说明](../../reference/README.md)。描述继承原 PRD 的静态分析，不代表本次完成运行验证。

原 D17–D19 指向未随归档提供的外部附件，不能作为可查阅源文件。产品与 RSS 的职责、需求分级和 T3 约束已明确写入本仓 [范围规则](../rules/project-scope.md) 与 [验证规则](../rules/verification-scope.md)，正文改为引用这些规则，不伪造缺失附件。

<a id="d01"></a>

- **D01** `README.md`：仓库当前状态与前端边界。

<a id="d02"></a>

- **D02** `docs/product/prd-v6.md`：MVP 正式 PRD v6；保留原始功能编号。

<a id="d03"></a>

- **D03** `docs/product/raw-requirements.md`：原始需求输入，非现行完成事实。

<a id="d04"></a>

- **D04** `docs/product/roadmaps/phase-1-roadmap.md`：Phase 1 正式路线图 019–024。

<a id="d05"></a>

- **D05** `docs/product/roadmaps/phase-2.md`：Phase 2 v1.1；元数据 official，正文 Draft。

<a id="d06"></a>

- **D06** `docs/product/proposals/prd-v7-optimizations.md`：PRD v7 优化提案，未当成正式替代基线。

<a id="d07"></a>

- **D07** `docs/product/roadmaps/mdm-native-rebuild-roadmap.md`：原生 MDM 从零重建路线图；仅覆盖 MDM 通道。

<a id="d08"></a>

- **D08** `docs/product/roadmaps/202603211800-046-commercial-gap-and-agent-roadmap.md`：2026-03-21 商用差距与 Agent A–D 草案。

<a id="d09"></a>

- **D09** `docs/product/041-capability-closure-deep-review.md`：历史能力闭环审查，需逐项与当前代码复核。

<a id="d10"></a>

- **D10** `docs/product/042-closure-capability-packages.md`：历史六类闭环能力包；用于风险分类而非当前缺陷断言。

<a id="d11"></a>

- **D11** `docs/product/043-mdm-framework-completeness-impact-after-025-027-032.md`：025/027/032 后 MDM 完整性分析。

<a id="d12"></a>

- **D12** `docs/product/044-agent-extension-attribute-completeness-assessment.md`：Agent / EA 完整性历史评估。

<a id="d13"></a>

- **D13** `docs/product/045-mdm-driven-extension-attributes-feasibility.md`：MDM-first 扩展属性边界与建议。

<a id="d14"></a>

- **D14** `docs/product/roadmaps/202603161710-220-phase2-generic-csp-pruning-review.md`：通用 CSP 完成后的条件性裁剪建议。

<a id="d15"></a>

- **D15** `specs/029-advanced-search-engine/spec.md`：当前高级搜索规格；不是 Phase 2 的 029 脚本库。

<a id="d16"></a>

- **D16** `specs/030-setup-wizard/spec.md`：当前初始化向导规格；不是 Phase 2 的 030 扩展属性。

<a id="c01"></a>

- **C01** `src/cmd/api/main.go`：API 装配、RBAC、设备/搜索/设置/SSO 路由。

<a id="c02"></a>

- **C02** `src/cmd/mdm/main.go`：MDM 装配、outbox、WNS 热重载。

<a id="c03"></a>

- **C03** `src/cmd/group/main.go`：智能组 SQL/事件消费/事务消息接线。

<a id="c04"></a>

- **C04** `src/cmd/policy/main.go`：PolicyReconciler / outbox 生产接线。

<a id="c05"></a>

- **C05** `src/internal/api/agent/router.go`：Agent 注册、签到、ack 与鉴权路由。

<a id="c06"></a>

- **C06** `src-agent/engine/poller.go`：真实 Agent 轮询主链；收到命令只校验和写日志。

<a id="c07"></a>

- **C07** `src/internal/domain/agent/repository.go`：Agent TaskRepository 无 Create 接口。

<a id="c08"></a>

- **C08** `src/internal/application/provider/registry_setup.go`：12 项内置 CSP Provider 注册；通用与专用并存。

<a id="c09"></a>

- **C09** `src/internal/application/provider/windows_csp_config.go`：syncml_manifest/v1 翻译、结构校验、DDF warning、cleanup。

<a id="c10"></a>

- **C10** `src/internal/application/group/recalculator.go`：智能组重算、成员变更与持久化。

<a id="c11"></a>

- **C11** `src/internal/domain/policy/scope_resolver.go`：Scope / Limitation / Exclusion 解析。

<a id="c12"></a>

- **C12** `src/internal/application/policy/reconciler.go`：期望执行与实际执行状态收敛。

<a id="c13"></a>

- **C13** `src/internal/application/mdm/management_service.go`：SyncML 会话、命令派发、Status/Results、采集与合规。

<a id="c14"></a>

- **C14** `src/internal/domain/device/read_model.go`：统一设备 CQRS 模型、通道与生命周期字段。

<a id="c15"></a>

- **C15** `src/internal/application/device/projector.go`：设备跨通道读模型投影与事件消费。

<a id="c16"></a>

- **C16** `src/internal/application/audit/service.go`：审计缓冲、重试、溢写与剩余丢弃路径。

<a id="c17"></a>

- **C17** `src/internal/application/sso/sso_login_service.go`：OIDC 回调、JIT、组映射、角色分配。

<a id="c18"></a>

- **C18** `src/internal/application/auth/service.go`：本地认证与内部有效主体校验。

<a id="c19"></a>

- **C19** `src/internal/application/search/service.go`：高级搜索、选列、保存查询业务实现。

<a id="c20"></a>

- **C20** `src/internal/application/setup/service.go`：Setup 模式与基础设施配置实现。

<a id="c21"></a>

- **C21** `src/internal/application/resource/service.go`：资源、版本、文件及生命周期实现。

<a id="c22"></a>

- **C22** `src/internal/application/mdm/device_lifecycle_service.go`：退役、证书撤销、取消命令、重新激活。

<a id="c23"></a>

- **C23** `src/internal/application/device/lifecycle_service.go`：上层双通道退役/重新激活编排。

<a id="c24"></a>

- **C24** `src/internal/application/mdm/device_action_service.go`：远程动作、队列与命令重试。

<a id="c25"></a>

- **C25** `src/internal/domain/mdm/command.go`：MDM 命令状态机。

<a id="c26"></a>

- **C26** `src/internal/domain/policy/value_object.go`：策略、版本、执行状态与策略类型。

<a id="c27"></a>

- **C27** `src/internal/domain/agent/task.go`：Agent 当前任务状态流转。

<a id="c28"></a>

- **C28** `src-agent/storage/queue.go`：Agent SQLite 离线队列组件。

<a id="c29"></a>

- **C29** `src/internal/application/collection/service.go`：可配置采集模板与 DDF 可读节点导入。

<a id="c30"></a>

- **C30** `src/internal/application/ddf/manifest_validator.go`：DDF 元数据校验当前为告警语义。

<a id="c31"></a>

- **C31** `src/internal/domain/mdm/compliance.go`：当前合规状态枚举与命令状态聚合。

<a id="c32"></a>

- **C32** `src/internal/domain/provider/provider.go`：PlatformMacOS 预留、SyncMLCommand 固定输出、AgentTaskPayload 与 Capability/PlatformProvider；
