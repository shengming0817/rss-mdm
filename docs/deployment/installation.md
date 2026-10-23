# 候选构建与安装

## 构建当前候选

候选格式为 V1。自有 SQL 直接建立最终结构，安装清单由二进制 `--describe` 唯一派生；服务与安装器必须输出同一清单。V1 是当前格式标识，具体内容由完整 Git revision、schema 指纹和候选摘要固定。

构建使用当前工作区源码，包含未提交修改、已加入 Git 索引的新文件及删除；源码路径由 workspace 成员与构建输入限定。范围内未跟踪文件默认拒绝，新增源码须先逐项检查并加入索引，不要求 commit 或 clean HEAD。复制前后核对文件内容与状态，变化则终止构建；candidate 记录实际复制输入的摘要，运行验收不依赖源码 checkout。构建机需要 Docker Buildx 和私有 Git 只读凭据。部署宿主使用 macOS 或 Linux，arm64 或 amd64；容器平台显式选择 `linux/arm64` 或 `linux/amd64`，不要求宿主安装 Rust、nginx、systemd 或使用 sudo。后端可独立发布；前后端一起交付时，额外提供不可变 rss-web MDM image ID/repository digest。

```sh
# 仅后端
python3 hack/release.py --output artifacts/candidate --git-auth-header-file /private/azure-header
# 前后端一起交付（选择新的输出目录）
python3 hack/release.py --output artifacts/combined --git-auth-header-file /private/azure-header --web-image "$MDM_UI_IMAGE_ID"
python3 hack/build_run.py -- python3 hack/candidate_smoke.py --candidate artifacts/candidate
```

授权头文件须为 owner 独占普通文件，只以 BuildKit secret 供依赖获取使用。构建从一次源码副本生成正式 OCI，复用正常缓存；失败不发布候选目录，已有输出不覆盖。

V1 候选包含 server.oci.tar、installer.oci.tar、candidate.json、正式 `deployment/production.compose.yaml`、卷输入准备程序、角色 SQL、网关配置和设备证书模板。`--web-image` 固定并归档真实 MDM 控制台；正式控制台部署必须包含它。用 `--platform linux/arm64` 或 `--platform linux/amd64` 指定容器架构，服务、安装器和 UI 必须一致；省略时使用 Docker 默认平台并核验实际 OCI。macOS arm64 上运行 amd64 容器属于仿真，不能作为 amd64 宿主已验收的证据。

安装器只以容器镜像交付，不再交付宿主 Linux 二进制。服务和安装器默认 UID/GID 10001。manifest 固定实际镜像身份、平台、归档和部署输入摘要；旧候选须重建，不提供旧 systemd 安装目录转换。恢复前核验归档和部署输入，不以 tag 替换已交付镜像。

安装、smoke 与认证验收不要求 matching checkout、Git 元数据或 clean HEAD。把运行工具与候选放到独立目录也可执行，工具从候选目录读取角色和网关文件。候选摘要保护所交付内容的一致性，不替代分发渠道信任。

smoke 启动实际 OCI、自有 TLS PostgreSQL 与 HTTPS 网关，验证迁移、初始化、权限、重放、健康与关闭；不构建第二个消费者。仅后端候选使用固定 nginx 依赖提供 HTTPS API 代理，页面路径返回 404；包含前端的候选使用交付的前端镜像提供页面。浏览器认证验收要求包含前端，缺失时明确拒绝并提示使用 `--web-image` 重建。成功与资源清理完成后才发布 smoke.json/smoke.log，失败移除旧成功标记并保存脱敏诊断。真机 T3 另行提供。

## 全新实例安装

基础 Compose 声明 PostgreSQL、一次性 `init`、`server`、独立静态 `web` 和 `gateway`，提供可登录的管理环境；完整服务端 SIT 还须完成[下文的 CA、内容存储与通道接线](#服务端-sit-部署)。不挂 Docker socket、不使用宿主 systemd/root/host 网络。产品初始化只建立真实 schema、稳定安装身份、独立平台/业务管理员、首业务租户和基础授权，并导出运行配置；不创建或管理容器，不写模拟设备或业务成功记录。

部署方准备私有目录，提供：`database-password`、`platform-password`、`administrator-password`、`postgres-ca.crt`、`postgres.crt`、`postgres.key`、`gateway-ca.crt`、`gateway.crt`、`gateway.key`。PostgreSQL 证书覆盖 DNS `postgres`；网关证书覆盖公开 HTTPS 域名。密码由组织秘密管理提供，不使用公共默认密码。目录与秘密文件分别设为 0700/0600。

本机 T3 可使用 OpenSSL 创建专用测试 CA 与真实 TLS 证书，仍走同一正式初始化入口：

```sh
mkdir -m 700 /absolute/mdm-secrets
# 在这个私有目录内执行；生产使用组织提供的证书与秘密。
umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj '/CN=MDM local TLS CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash' -keyout ca.key -out ca.crt
for pair in postgres:postgres gateway:mdm.example.test; do
  name=${pair%%:*}; dns=${pair#*:}
  printf 'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$dns" > leaf.ext
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$dns" -keyout "$name.key" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 90 -extfile leaf.ext -out "$name.crt"
  cp ca.crt "$name-ca.crt"
done
for name in database-password platform-password administrator-password; do openssl rand -hex 24 > "$name"; done
```

候选归档通过 `docker load -i server.oci.tar`、`docker load -i installer.oci.tar` 和 `docker load -i identity-ui.image.tar` 导入。按 candidate.json 的固定镜像选择设置环境；Compose 使用当前 Docker context，无宿主 socket 路径准备：

```sh
export MDM_SERVER_IMAGE='实际后端镜像ID或摘要'
export MDM_INSTALLER_IMAGE='实际初始化镜像ID或摘要'
export MDM_WEB_IMAGE='实际MDM前端镜像ID或摘要'
export MDM_GATEWAY_IMAGE='候选providers.nginx的固定镜像'
export MDM_POSTGRES_IMAGE='候选providers.postgres的固定镜像'
export MDM_INPUT_DIRECTORY=/absolute/mdm-secrets
export MDM_PRODUCT_ORIGIN=https://mdm.example.test
export MDM_PUBLISH_ADDRESS=0.0.0.0:443
export MDM_INGRESS_SUBNET=172.30.86.0/24
export MDM_GATEWAY_ADDRESS=172.30.86.2
export MDM_BACKEND_ADDRESS=172.30.86.3
# 文件来自固定候选的 deployment 目录。
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml up -d
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml ps --all
```

`init` 等待数据库健康后运行并退出；`server` 仅在 init 成功后启动。init 的短暂容器内 root 只将部署 secrets 复制为卷内 0600 文件，然后降为 UID10001 执行 Rust 初始化；没有宿主 root 操作或基础设施管理权限。运行后端、网关均为 UID10001，分别只读挂载自己的运行子目录；PostgreSQL 由官方镜像管理数据属主。

`installation.json` 的 `stage=initialized` 表示种子初始化完成，不宣称网络或设备效果。检查 HTTPS `/readyz`、实际登录和授权后，用原安装输入执行一次真实宿主观察：

```sh
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint /usr/local/bin/rss-mdm-installer init prepare-hosts --config /var/lib/rss-mdm/installation-input.json
```

平台开通回执中的首租户必须从 `host_pending` 变为 `enabled`，再进行业务通道设置、轮换材料、备份和开始 T3；此命令只观察已启动服务，不管理容器。平台登录名为 `platform`，业务登录名为 `administrator`，密码分别取自部署 secrets。将 `gateway-ca.crt` 的公共证书加入专用浏览器/设备信任；CA 私钥不交付客户端。

用相同 secrets、相同卷重复 `docker compose ... run --rm init` 保持原 tenant/principal/instance/operation、密码和密钥。安装已完成时不覆盖后续配置。停止、重建与重启使用普通 Compose 命令；`down` 保留卷，`down -v` 删除数据，不能用来恢复故障。没有常驻 operator 或自动创建子 Compose 的进程。

### 服务端 SIT 部署

服务端 SIT 交付包含可登录的基础环境、真实设备 CA、内容存储、任务签名、注册设置、已启用通道和运行检查。真实 Mac/Windows、Agent 安装、系统权限与设备注册结果属于后续测试准备和测试结果，不作为服务端部署完成条件。服务健康也不表示设备测试已经通过。

本地基础设施使用交付的 `deployment/sit.compose.yaml` 叠加基础 Compose，复用准备好的持久卷；已有外部 CA/S3 则沿本节的产品接线流程使用其真实地址和信任，不再启动本地副本。两种方式都不消费 `make dev`、T2 fixture 或受控假后端。

| 本地服务 / 卷 | 部署方已有材料与持久状态 |
|---|---|
| `step-ca` / `MDM_CA_VOLUME` | `/home/step/config/ca.json`、公开根/issuer、加密中间 CA 密钥、原 CA 数据库、`/home/step/password`；DNS 覆盖 `step-ca`，监听 9000；Agent、Windows、Apple 使用各自 provisioner |
| `rustfs` / `MDM_RUSTFS_VOLUME` | 原 RustFS 数据，服务 UID/GID 10001 可读写 |
| `MDM_RUSTFS_TLS_VOLUME` | `rustfs_cert.pem`、匹配的 `rustfs_key.pem`、`ca.crt`、`access-key`、`secret-key`；证书覆盖内部 DNS `rustfs`，凭据文件为部署管理员专用 |

这些是外部卷，模板不会创建空目录冒充材料、覆盖原数据或生成新的 CA 身份。新建 SIT 时先由基础设施运维使用固定 step-ca 官方 CLI 初始化 CA 卷、配置 remote management 和签名 CRL，并将根私钥及独立解密密码转移到未挂载的离线目录；普通重放直接复用原卷。CA 目录与秘密须由容器 UID10001 读取，文件 0600、目录 0700；属主准备在一次性维护容器内完成，不在 macOS/Linux 宿主执行 chown 或 systemd 操作。在线 CA 不挂载离线根钥，MDM 运行容器不挂载 CA 管理凭据或 RustFS 管理员凭据。

SIT 的原 CA 配置 `/home/step/config/ca.json` 使用以下 CRL 策略；只修改该节，保留原证书、密钥、数据库、provisioner 和其余配置：

```json
"crl": {
  "enabled": true,
  "generateOnRevoke": true,
  "cacheDuration": "168h",
  "renewPeriod": "1h"
}
```

这是 step-ca 的基础设施配置，由原 CA 卷持有；MDM 的 `step-ca.json` 接入输入保持不变。有效期为 7 天，每小时生成新 CRL，吊销时立即生成；产品每 60 秒获取并验证。已有 CA 修改后用普通 Compose 重启 `step-ca`，核对实际 CRL 的 `thisUpdate` / `nextUpdate` 及各已启用用途的接收结果；重启本身不能证明新策略已发布。停机维护和恢复见[设备 PKI 运维](operations.md#设备-pki-轮换与撤销)。

`sit.compose.yaml` 的 CA 仅开放容器网络，RustFS 禁用控制台且不发布宿主端口。CA 官方二进制携带绑定端口的文件 capability，服务只保留 `NET_BIND_SERVICE`，仍以 UID10001 运行。RustFS 使用独立受信 TLS，不能关闭校验。数据和 TLS 卷名默认见模板；不同部署设置各自的 `MDM_*_VOLUME`，不能共享可写 CA 数据库或 RustFS 数据目录。

从固定候选 `deployment/providers.lock.json` 设置 `MDM_STEP_CA_IMAGE` 和 `MDM_RUSTFS_IMAGE`，沿用基础安装的环境文件与项目名：

```sh
# compose.env 保留原镜像、输入目录、域名、项目名及持久卷配置。
# 两个新增镜像分别取 providers.lock.json 的 step-ca / rustfs，不使用 latest。
# 将基础 Compose、原有卷 override 和 SIT 文件的绝对路径加入 COMPOSE_FILE。
docker compose --env-file /absolute/sit/compose.env config --quiet
docker compose --env-file /absolute/sit/compose.env up -d step-ca rustfs
```

接线按下面顺序执行一次，保留维护输入、操作 UUID 和回执。变更通过原领域 API/维护 CLI 完成；不能修改生成的 `runtime.json` 或写 SQL 伪造就绪。

新实例使用 S3 作为内容后端时，在首次 `init` 前设置 `MDM_CONTENT_STORAGE=s3` 并保留在部署环境中。该选项暂缓首次内容存储绑定；准备下述租户连接后，由 `prepare-hosts` 导出 S3 配置，再重建服务完成首次准入。默认 `volume` 使用持久内容卷。已经绑定的后端不能通过修改这个选项或重放初始化来迁移，须保留原内容身份和数据。

1. **基础初始化**：沿上节启动一次性 `init` 和管理服务，取得原安装回执及首租户身份，使用真实业务管理员登录。后续维护从原 `installation-input.json` 派生独立输入，不修改首次安装输入。
2. **内容存储**：确认实际桶存在并开启版本控制，在维护输入的 `storage_profiles` 登记真实 endpoint、region、bucket、namespace、CA 和部署管理员文件引用。业务管理员向 `POST /api/v1/storage/connections` 提交 `{"expectedRevision":0,"profile":"sit-rustfs","source":{"kind":"generate"}}` 及稳定 `Idempotency-Key`。初始 revision 仅适用于未创建连接的租户；已有连接先读目录。执行原 `prepare-hosts`，完成受限工作负载身份、真实版本化读写/删除及跨租户前缀拒绝检查，回执须为 `qualified` 且被选中。运行端只取得加密持久化的工作负载版本，不使用管理员身份。
3. **任务签名**：通过 `POST /api/v1/task-signing/trust` 提交 `{"action":"prepare","expectedRevision":0}` 及稳定 `Idempotency-Key`。无已注册 Agent 的首把密钥由原 owner 生成并加密保存为 active；重放原操作，不再生成另一把钥。已有权威遵循原轮换流程。执行 `prepare-hosts` 导出期望版本，按下方命令重建服务并复验。
4. **设备 CA**：只准备下方的一份 `step-ca.json`。先通过 channels 保存需要启用的通道及最终 443 origin（缺材料可为空）；随后 SIT 的独立 `ca-init` 调用统一初始化，发现真实签发者、准备所有用途、安装固定模板及回调、生成或复用凭据并导出网关。无需填写 purpose、provisioner、kid、模板、回调或每用途操作 ID。已有管理员、租户、设备、历史信任和签发材料保留。
5. **通道**：使用原 `configure-host` 的 `channels` 变更，CA 信任和回调从统一初始化结果自动接入，不再手填 trust/provider；Agent 标准证书期限为 `{"mode":"standard"}`，Windows 为 `{"mode":"production"}`。Agent、Windows 注册、Windows 管理和 Apple 默认共享 HTTPS 域名及端口，也可分别配置；网关服务器证书覆盖全部公开名称。Windows 配置显式轮询计划，可在无 WNS 时使用轮询。Rust 仅使用隔离网络内的单个 HTTP 地址，Nginx 终止 TLS/mTLS、分流协议路径并覆盖证书证据；内部端口不公开。
6. **恢复材料与注册**：需要凭据托管的 SIT 使用原 `configure-host` 的 `recovery` / `recipient.kind=generate`，幂等保存独立加密保护材料及接收证书。核对 `/api/v1/agent-enrollment-settings` 启用 Windows/macOS，并核对 `/api/v1/registration-channels` 的已选通道准入；已有租户规则保留，修改须使用当前 revision。Group/Scope/Policy 等测试业务对象由测试场景创建，不预置假设备或完成记录。

配置导出后，运维重建服务，再复验原操作：

```sh
docker compose --env-file /absolute/sit/compose.env up -d --no-deps --force-recreate server gateway
# 复用已导入卷内的原请求，保留原 operation_id / expected_revision。
docker compose --env-file /absolute/sit/compose.env run --rm --no-deps --user 10001:10001 \
  --entrypoint /usr/local/bin/rss-mdm-installer init configure-host --config /var/lib/rss-mdm/channels-request.json
docker compose --env-file /absolute/sit/compose.env run --rm --no-deps --user 10001:10001 \
  --entrypoint /usr/local/bin/rss-mdm-installer init prepare-hosts --config /var/lib/rss-mdm/maintenance.json
```

维护输入、证书和秘密导入命名卷的方法见[Compose 维护材料](operations.md#compose-维护材料与数据库-tls-续期)。每次配置变更单独完成导出、重建、原操作复验，再进入下一项；`applied=null`、仅文件保存或历史观察均不能算已加载。

服务端 SIT 部署检查必须覆盖：

- PostgreSQL、CA、RustFS 健康；`/readyz` 中当前进程观察与期望 revision、材料摘要、原租户/实例匹配。
- 原平台/业务管理员均能登录并取得各自授权；匿名管理请求被拒绝，设备保护接口要求真实客户端证书。Agent 公开 trust 可经真实域名 HTTPS 读取，Windows 管理入口无客户端证书时 TLS 拒绝。
- Agent 与 Windows 通道分别返回 `availability=ready`，准入符合租户设置；内容连接为 `qualified` 且实际运行加载对应 revision，任务签名存在 active key，所选恢复材料已加载；正式 `/api/v1/audit-events` 可查询。
- 用相同输入至少重放一次 `init`，租户、管理员、instance、operation、密码与保护材料不变；重放 CA 准备保持原 issuer/kid；重启依赖并按上述顺序重建 server/gateway 后再次通过运行观察。
- 保存 Compose 环境、固定镜像、维护操作回执和一致数据库/材料备份；不把运行中的卷简单打包作为一致备份。备份和恢复边界见[运维指南](operations.md#当前安装联合冷备)。

Apple 原生 MDM 纳入完整部署清单：通过 channels 配置保存 Apple 入口与启用意图，`materials.apns`、`materials.profile` 可暂为 null。缺 APNs/Profile 或安全材料时显示 waiting/degraded，管理面继续服务。内部 CA 由独立 ca-init 准备，不作为核心 server 的健康启动依赖；APNs 出站与真实组织资格单独验收。ADE、WNS、OIDC、邮件与 Webhook 按所选集成准备真实外部材料。Agent 安装包发布、终端注册和真实任务效果在环境交付后测试，不通过 fixture 或手动勾选状态补成成功。

### 后续租户与运行容量

正式平台会话调用 provisionings API 创建真实租户、管理员和授权。保留每业务进程绑定一个租户的拓扑。账户就绪不意味着运维已部署对应服务；宿主未启动时回执保持 `host_pending`，不会伪报 enabled。

在独立维护输入中沿用原安装配置，追加 `additional_hosts`，每项提供 `origin`、内部 `listen` 和 `deployment`：后者包含运行输出 `directory`、共享 `gateway_directory`、可选 `probe_address`、TLS 文件及可选内容目录，不含镜像、网络或容器参数。例如输出目录 `/var/lib/rss-mdm/runtime/second`，probe 为 `gateway:8443`，`gateway_directory` 与主宿主相同。将维护 JSON 导入安装卷后执行一次 `prepare-hosts`，生成运行文件；无需改首次安装输入，也不重做种子初始化。命令及秘密导入方式见[维护材料](operations.md#compose-维护材料与数据库-tls-续期)。

运维使用候选中的 `tenant.compose.yaml` 直接声明新租户实例，沿用主安装的 state、content 卷和数据库网络，设置：

```sh
export MDM_STATE_VOLUME=rss-mdm_state MDM_CONTENT_VOLUME=rss-mdm_content MDM_NETWORK=rss-mdm_default
export MDM_RUNTIME_SUBPATH=runtime/second MDM_SERVER_ALIAS=second-server
export MDM_INGRESS_NETWORK=rss-mdm_ingress
export MDM_BACKEND_ADDRESS=172.30.86.4
docker compose -p rss-mdm-second -f /absolute/candidate/deployment/tenant.compose.yaml up -d
```

新宿主使用不同的公开 hostname，仍共用同一公网 443；证书覆盖该 hostname。宿主输入导出后先运行 `deployment/render_gateway.py`，再执行 gateway 的 `nginx -t -c /run/gateway/nginx.conf`，成功后通过 `nginx -s reload -c /run/gateway/nginx.conf` 应用新 SNI/HTTP 配置。再次显式运行 `prepare-hosts`，它只通过 HTTPS 读取实际 readyz 并核对租户、安装、配置版本及进程代次，然后记录 enabled；不启动、重启或停止服务。容量由运维的 Compose/Kubernetes 声明持有，租户授权和业务数据隔离仍由产品持有。配置应用和供应方核验同样通过一次性维护命令执行，无后台部署轮询。

### 单机部署设计与配置归属

Docker Desktop/Engine 可承载 MDM 后端、HTTPS 网关、PostgreSQL，以及按所选设备能力准备的对象存储和设备 CA。Identity 嵌入后端，Windows/Mac 与 Agent 在设备侧。本次正式交付为 Compose；Kubernetes/HA 未提供交付或验收承诺。

默认公网只发布 gateway 的 TCP 443（容器内无特权监听 8443）；分离端口须应用 renderer 生成的 ports override。gateway、web、server 使用各自网络命名空间：gateway 与 server 通过专用 ingress bridge 通信，web 只连接 frontend 网络。后端管理监听使用明确的内部地址，`trusted_gateway` 只信任该网络的固定 gateway IP；不能配置整个子网或接受外部身份头。多租户按不同 hostname 分流，各自使用独立 server 地址，网关共享配置由 `deployment.gateway_directory` 汇集。

| 默认同域入口（HTTPS 443） | 流向与身份核验 |
|---|---|
| `mdm.example.test/` | Nginx → web:8080 静态页面 |
| `mdm.example.test/api/` | Nginx → 唯一内部 HTTP 入口；管理会话、CSRF 与权限由后端验证 |
| `mdm.example.test/EnrollmentServer/...` | 同一入口的 Windows 注册路由；后端验证原生凭据 |
| `mdm.example.test/ManagementServer/...` | 同一入口的 Windows 管理路由；后端验证设备证书 |
| `mdm.example.test/checkin`、`/mdm`、`/native/apple/ddm/...` | 同一入口的 Apple 路由；材料未就绪时拒绝业务请求 |
| `mdm.example.test/api/v1/agent/...` | 同一入口的 Agent 路由；注册与已注册设备操作保留各自准入要求 |
| `mdm.example.test/scep/...` | Nginx 精确路由 → 私有 CA HTTPS；不发布 CA 管理或通用签发接口 |

需要分离时，各原生 endpoint 与 Agent 首选/候选配置分别指定完整 HTTPS origin；每个域名、端口都必须完成证书、部署与观察检查。
所有 hostname 必须解析到公网入口，证书 SAN 覆盖对应名称。未知/缺失 SNI 及 SNI/Host 不一致均拒绝。Nginx 终止 TLS/mTLS，并在隔离的 HTTP 接缝覆盖真实来源、公开 origin 和 TLS 叶证书证据；Rust 核验实际 socket gateway 后独立验证设备用途与权限。浏览器管理入口保持 Cookie、Origin、CSRF 和请求预算约束。

新部署默认只需一个公网端口；分离端口由部署层显式发布。本方案不提供旧部署迁移、旧格式升级或兼容 overlay。设备身份材料、CA 私钥、数据库秘密不交付 web 容器；PostgreSQL、RustFS 和 CA 保持内部连接及独立 TLS。

SIT 默认共用一个 step-ca/root/issuer，按用途配置独立 provisioner：Agent 为 `rss-agent` JWK，Windows 为 `rss-windows` JWK，Apple 为 `rss` SCEP 及独立的 `rss-apple-revocation` 撤销凭据。各用途保留自己的模板、授权、信任与证书记录，不能只凭共享 issuer 接受其它通道身份。CA 数据库和 CRL 属于同一物理签发者，按一套基础设施停写、备份和恢复；产品的用途记录仍分别保留。原分离部署通过现有 PKI 轮换与退役接口收敛，不清库或替换现有设备身份。相关边界见[设备 PKI 运维](operations.md#设备-pki-轮换与撤销)。

| 输入或产物 | 当前 owner 与操作入口 |
|---|---|
| 镜像、网关 TLS、监听、数据库引导连接、可用宿主槽位 | 运维提供一份[安装输入](../../crates/app/src/setup/installation.rs)，冻结真实镜像 ID/digest；运维持有部署权限，产品命令只导出运行输入，业务 API 不接收任意命令/路径 |
| instance/tenant/principal/operation、target/lineage、角色密码及安装保护材料 | 安装器生成并持久保存；首租户、独立平台/业务身份及授权由同一安装流程准备，重放不手工换 ID 或重置密码 |
| 运行快照、网关配置、公开宿主 JSON 与应用摘要 | 由安装/宿主应用 owner 派生；原操作冻结实际文件字节，不能编辑生成文件绕过期望版本及进程观察 |
| 用户、授权、注册设置、Group/Scope/Policy、软件与 Apple 组织 | 真实租户会话调用原领域 API；平台会话不自动获得业务数据权限，目录查询不成为第二个写 owner |
| APNs/Profile/Managed Apple Account、WNS、任务签名、SMTP、Webhook、S3 凭据 | 原领域 API 管理加密材料、版本与适用校验；部分变更直接生效，需运行应用的变更由部署 owner 执行，分别核对 requested/applied 与真实效果，见[运维指南](operations.md) |
| 设备 CA、OIDC 宿主准入、通道和恢复材料的部署设置 | 使用 `initialize-ca`、`configure-host` 及各领域接口；密钥轮换使用对应流程，不把原始 CA 私钥或任意内网准入交给租户 |
| 设备私钥、CSR、注册回执、Agent 本机 trust 与运行 journal | 由设备/注册 owner 生成持久保存；服务端只授权并分发所需公开材料，端侧部署由 [Agent 指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop)维护 |

安装目录及数据库/材料秘密位于源码仓之外。私有目录、普通秘密文件和读取者权限按现有安装与 CA 规则设置，不使用符号链接或将整个部署根目录挂入运行容器。根私钥及离线根密码独立保管，在线 CA 只取得必要中间签发材料；初始化的 CA 管理凭据、SCEP 解密私钥不进入 MDM 运行宿主。服务 TLS 根、设备 issuer、Profile 签名身份和 APNs 身份分别校验，不能互相替代。

先安装可登录的基础管理宿主，再由授权会话导入组织材料，经原领域校验和受控宿主应用启用通道。缺少 APNs 等外部材料时明确保持相应通道关闭；材料保存、CA 准备通过、当前进程已加载与设备实际生效分别记录。S3 通过受限 `storage_profiles` 和下节连接流程准备，工作负载凭据不使用 RustFS root 身份，必须验证真实版本化及跨租户前缀拒绝。

### 对象存储开通与凭据更新

部署输入 `storage_profiles` 列出允许使用的 HTTPS S3 端点、region、bucket、基础 namespace 和 CA 文件。`rustfs_administrator` 只供部署进程执行固定 IAM 创建动作；导入其它 S3 凭据时提供 `boundary_verifier`，用于确认租户前缀之外的实际对象确实存在。管理 HTTP 只接受 profile 名称，不能提交任意端点或部署管理员材料。

业务管理员调用 `POST /api/v1/storage/connections`，携带 UUID `Idempotency-Key`，请求包含 `expectedRevision`、`profile`、`source`。`source.kind=generate` 在领域保护侧生成 RustFS 工作负载身份；`source.kind=import` 导入 `access_key`、`secret_key`，可选 `session_token` 和 `expires_at`，临时 token 必须有有效期限。材料加密入库后返回 202，供应方准备异步执行。`GET /api/v1/storage/connections` 投影当前目录；`GET /api/v1/storage/connections/operations/{id}` 查询原操作，未知提交不得换操作 ID 重建凭据。

部署进程在首次外部调用前固定端点、桶、命名空间与信任材料。自动创建验证 IAM 用户、策略和绑定；两条路径都验证 TLS、桶版本控制、真实版本化读写、精确版本删除以及对已确认存在的外部前缀对象的拒绝。失败保持原操作和凭据，可恢复重试；运行服务无权限自行标记供应方校验成功。桶须预先存在并启用版本控制。每个租户使用 `namespace/<tenant UUID>`；更新凭据不能改绑到其它桶或前缀。

合格版本进入宿主期望配置，经固定部署进程重启和真实 HTTPS 观察后才算应用。运行配置 `content.storage` 只引用材料 `revision`，不再接受 S3 端点或凭据文件。旧有效版本可支撑失败回退；过期或撤销材料在实际内容操作时被拒绝。资格回执是当次验证证据，不代表供应方永久健康。



MDM 宿主使用同一份运行配置生成两份公开 bootstrap 输入：`ui.json` 的
`canonicalOrigin/oidcEnabled` 和 `mdm.json` 的 `canonicalOrigin/tenant`。
部署网关分别在 `/api/v1/identity-host/config.json`、`/api/v1/mdm-host/config.json` 精确提供这些文件，
不得填入凭据或另设租户权威。环境初始化与候选运行工具从 `product_origin`、`identity` 自动生成，
手工部署须将相同公开字段只读挂载到网关。

`/api/v1/mdm-candidate/workspace` 返回当前会话的真实模块导航提示；提示不授予权限。
Identity callback 固定 `/api/v1/identity/oidc/callback`，其它 API 保留后端路由和错误，不能落入 SPA。
这些宿主配置和 HTTP 接缝由后端验证；前端消费和页面验收由前端 owner 负责。

原生采集持久恢复采用当前 execution schema；旧安装清单拒绝接入，无原地转换或双读。重新安装须使用独立空库，安装器不会自动清理已有数据库。

使用 candidate.json 固定的依赖和二进制 --describe 声明的安装单元。接受空库或完全一致的当前安装记录；失败恢复见[运维](operations.md)。

由数据库管理员创建专用数据库和 `mdm_owner`、`mdm_runtime`、`mdm_api`、`mdm_access` 基础角色。所有产品角色均禁止 SUPERUSER、BYPASSRLS 和高权继承；`mdm_owner` 需要该数据库与 public schema 的 CREATE 权限，但不持有 CREATEROLE。`mdm_api` 是组件 reader 的验证角色，不进入 serve 配置。

再按顺序安装候选目录 deployment/ 中的 `software-publication-roles.sql`、`flow-roles.sql`、`identity-roles.sql`、`commands-roles.sql`、`audit-roles.sql`。脚本创建的 NOLOGIN profile 保持为权限角色；仅对实际配置的连接角色启用 LOGIN 并设置独立秘密，不额外授予继承权限。Identity runtime/maintenance/audit worker 不继承 owner；owner 的准入检查所需切换关系由随附 SQL 设置。

Audit 与 Ledger 的组件 SQL 分别由 `mdm_audit_owner`、`mdm_ledger_owner` 安装，两个 owner 均为 NOLOGIN、NOSUPERUSER、NOBYPASSRLS。管理员须对目标数据库执行 `audit-roles.sql` 中的 CREATE 授权。四类产品运行角色只取得组件表 SELECT 和固定写函数 EXECUTE；产品恢复回执位于 `mdm_audit.receipts`，使用租户 RLS 和 SELECT/INSERT 权限。

`migrate` 使用 mdm_owner；`initialize` / `recover-password` 使用 mdm_identity_maintenance；`initialize-authorization` 使用 mdm_access 显式初始化一次产品授权；`serve` 只使用对应运行角色。安装会检查实际 runtime/maintenance 和 audit worker 权限，脚本成功不代表角色准入成功。

迁移输入含 database 和 installation；installation 只固定 instance_id、target、lineage 和 audit_mode（plain 或 ledger，与运行配置 audit.mode 一致）。安装创建唯一保留管理租户及 epoch=1，不创建账户、密码或权限；重放只核稳定安装身份、保留管理租户绑定、完整当前 schema 和运行权限，不比较租户全集，不改租户 epoch。安装按 audit mode 授予 Identity audit worker 权限，模式不能随重放改变。

新增租户统一使用平台会话调用 `POST /api/v1/tenant-administration/provisionings`，包含 `name`、`administratorLogin`、`administratorPassword`，并提供 UUID `Idempotency-Key`。返回可查询开通回执；202 表示管理员或宿主阶段尚未完成，不能解释为租户已启用。旧裸创建 HTTP 入口与 `tenant-create` 命令已移除。元数据维护、查询和追加管理员保留独立用途。

下列维护命令由实际 `mdm_owner` 登录连接执行，使用 `--config /absolute/private-config.json`，公共输入为 database 和稳定 installation：

| 命令 | 其它输入 | 输出与约束 |
|---|---|---|
| `tenant-get` | tenant_id | 当前租户详情，包括 initial_epoch、current_epoch、name、notes、revision、deletable、management |
| `tenant-list` | 无 | 所有未删除租户详情，按 UUID 排序，最多 1024 个业务租户与 1 个管理租户 |
| `tenant-update` | tenant_id、expected_revision、operation_id；可选 name、notes | 全量替换元数据；省略或 null 清空字段；成功时 revision 加一，即使值未改变 |
| `tenant-delete` | tenant_id、expected_revision、operation_id | 仅允许删除从未声明使用的租户，revision 加一；保留墓碑、epoch、默认设置和回执 |
| `tenant-operation-status` | operation_id | 返回 committed 与原始 receipt，或 not_found 与 null |

tenant_id 与 instance_id 须为非空规范小写 UUID；operation_id 须为非空 UUID；initial_epoch 和 expected_revision 须为正整数。name 可为 null，否则最多 128 个 Unicode 字符且不能全为空白；notes 可为 null，否则最多 2048 个字符。元数据不控制权限或宿主绑定。tenant_id、installation 和 epoch 不通过更新命令修改；current_epoch 由 RSS fencing 持有。

容量按未删除业务租户计数，管理租户不计入 1024 上限，且不能更新、删除或作为业务宿主租户。删除释放容量，但租户 ID 永不复用。删除后新 get/update/delete 返回 NotFound，列表隐藏墓碑；没有强制删除、恢复、数据清扫、旧命令别名或旧 schema 迁移。旧安装与当前安装清单不匹配时拒绝运行，必须重新安装当前契约。

create/update/delete 的 operation_id 共用一个全局命名空间。同一操作、同一规范业务输入返回原始回执，包括删除后及后续元数据/epoch 改变后的重放；同操作异参、重复租户、过期版本或版本溢出拒绝。回执为 `{operationId, action, result}` 的提交时快照；数据库凭据不进入持久化业务请求。

提交确认丢失、命令超时或成功后连接清理失败时，保留 operation_id，使用 `tenant-operation-status` 查询回执，或用原输入重放。查询与写入共用安装级锁；锁等待失败不能解释成没有提交。`not_found` 仅表示查询取得锁后未发现已提交回执，不取消后来发起的操作。

账户初始化、授权初始化和 serve 在后续工作前，通过受限数据库能力核验安装身份、当前期望 epoch 和租户状态，并提交永久 used 标记。标记不改变元数据版本，后续初始化或启动失败也不会恢复可删除性。删除与首次使用共用安装锁；先删除则使用被拒绝，先声明使用则删除返回 InUse。运行角色仅有该固定函数 EXECUTE，不能直接更新租户表。

账户初始化输入另含 tenant_id、expected_epoch、principal_id、login、password_file；授权初始化沿用 user.tenantId 并显式提供 expectedEpoch。两者从数据库核验登记及当前 epoch，使用各自受限角色。日常账户与 IdP 管理使用受保护 HTTP 接口。

通过 `tenant-list` 找到 `management=true` 的唯一管理租户。部署方沿用现有 `initialize` 配置，把 tenant_id 填为该 ID、expected_epoch 填 1，显式创建初始账户；随后用同一账户执行 `initialize-authorization`，其 user.tenantId 也填该 ID。初始规则授予租户 CRUD、创建租户管理员、账户管理与授权读写，不授予设备业务权限。

账户、IdP 和业务授权统一保存在 authorization rules 中。旧 `identity_management` 配置已删除，提供该字段会被拒绝。管理租户初始主体持有 `identity_accounts_manage`、`authorization_read/write` 以及租户 CRUD、`tenant_administrator_create`；前三项受防锁死保护，其余可分别委派或撤销。管理租户不支持 IdP/联合登录。业务租户的账户与 IdP 管理分别使用 `identity_accounts_manage`、`identity_providers_manage`，规则变化即时生效。

可选 `tenant_administration` 配置启用租户管理 HTTP API；完全省略时七个入口均不挂载，配置不完整或权限不匹配会拒绝启动：

~~~json
{
  "tenant_administration": {
    "registry_database": {"host":"db","port":5432,"name":"mdm","user":"mdm_tenant_registry","password_file":"/run/mdm/registry-password","ca_file":"/run/mdm/ca.crt"},
    "provisioning_database": {"host":"db","port":5432,"name":"mdm","user":"mdm_identity_provisioning","password_file":"/run/mdm/provisioning-password","ca_file":"/run/mdm/ca.crt"},
    "fingerprint_key_file":"/run/mdm/tenant-operation-key"
  }
}
~~~

密钥文件为安装级固定 32 字节随机密钥，使用与其它秘密相同的文件保护；重启必须保留，用于请求 HMAC 指纹，不保存明文密码或快速密码摘要。两种数据库角色按安装 SQL 创建，仅赋予各自的 registry、provisioning、授权读取和审计权限；不要使用 mdm_owner 或维护凭据替代。管理 API 复用当前 HTTPS、origin、cookie、CSRF 与管理租户登录。

| 方法与路径（前缀 `/api/v1/tenant-administration`） | 请求 / 结果 |
|---|---|
| POST `/provisionings` | `name`、`administratorLogin`、`administratorPassword`；返回完整开通操作 |
| GET `/provisionings` | 开通操作分页列表；`after` 为上一页游标，`limit` 为 1–1000（默认 100）；返回 `items` 和 `nextAfter` |
| GET `/provisionings/{operationId}` | 查询原开通操作与当前恢复阶段 |
| GET `/tenants` | 未删除租户列表，包含保留管理租户 |
| GET `/tenants/{tenantId}` | 当前元数据 |
| PUT `/tenants/{tenantId}` | `expectedRevision` 与替换元数据 |
| DELETE `/tenants/{tenantId}` | JSON `expectedRevision` |
| POST `/tenants/{tenantId}/administrators` | `login`、`password` |
| GET `/operations/{operationId}` | 原始已提交回执；不存在为 404 |

所有写入仅从 `Idempotency-Key` 读取规范 UUID；JSON 拒绝未知字段。开通操作尚未完成时返回 202，完成及完成后的重放返回 200；其它写入成功及重放返回 200。回执统一为 `{operationId,action,result}`；CLI 的回执采用同一格式，字段使用 camelCase。相同操作号请求内容不同返回 409，重放保持最初结果与操作者，后续修改不改变回执。

创建管理员要求管理租户 `tenant_administrator_create` 及 300 秒内认证。服务生成新主体，原子写入账户、目标租户全部业务/设备 AllDevices 与账户/IdP 管理权限、审计和回执；不授予安装级租户管理权限，也不签发目标租户会话。可持续添加多个管理员；重复登录名返回 409，不重置或接管已有账户。重放会复核操作者当前会话与权限，但不重新赋权。开始账户初始化前永久登记首次使用，失败也不恢复可删除性。

每个宿主通过 identity.tenant_id 和 flow.storage.epoch 绑定一个已登记业务租户，启动核验安装身份、audit mode、登记和期望 epoch。同库其它租户使用各自合法绑定宿主；新增登记不自动切换已有宿主。

新实例使用前述 `install` 单输入入口，后续租户使用完整 provisionings 资源。`migrate`、`initialize` 与 `initialize-authorization` 保留给各自维护用途，不能组合成另一条公共租户创建路径。安装器按固定镜像身份准备运行输入，秘密由 UID 10001 持有且权限 0600；镜像不嵌入配置或私钥。

## 客户端入口与服务器证书交付

浏览器网关的 `/api/v1/mdm-host/config.json` 使用同一份静态配置交付 `canonicalOrigin`、业务 `tenant` 和平台 `managementTenant`。两类租户坐标由实际安装登记生成，只用于选择正式登录入口，不授予业务或平台权限。#2825 替换原来的两字段配置；部署必须同时更新生成配置和消费它的 Web 制品，不提供旧格式解析或第二个发现端点。

安装与宿主部署直接使用产品的公开配置生成器。需要为既有受控网关重新生成文件时，运行 `rss-mdm public-host-config --config /absolute/runtime.json`，标准输出仅含 `ui.json`、`mdm.json` 的公开 JSON；该命令使用运行配置中的数据库角色读取原安装的管理租户，不创建账户、会话或新身份。将两份 JSON 分别放入网关既有的只读配置位置。数据库不可用、租户坐标无效或业务与管理租户相同均失败，不能手填替代身份绕过。

网关加载部署方配置的服务器证书链与私钥。使用私有 CA 时，把签发该服务器证书的 CA 公共证书通过可信部署渠道分发到设备；CA 私钥留在部署端，不放入 Agent 配置、客户端安装包或前端静态资源。数据库连接的 `ca_file` 属于 PostgreSQL 信任，不复用为组织网关 CA。

服务端向桌面客户端部署方提供 HTTPS `product_origin`、绑定的 `identity.tenant_id` 和签发网关证书的 CA 公共证书。桌面构建与组织信任配置由 [rss-mdm-agent 桌面开发指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/desktop-development.md&version=GBdevelop) 维护。

服务端通过受保护安装渠道向 Agent 部署方交付绑定 `instance_id` 与 tenant 的注册文件、当前签名连接配置及验证公钥、HTTPS 服务器 CA 公共证书和设备 purpose trust。Agent 依据已发布连接配置使用首选和候选入口，地址变化不改变服务身份，也不扩展已授权 CA。控制台与 Agent 入口分别核对对应服务器证书；同 CA 签发时可交付同一公共证书。HTTPS 信任与设备 purpose trust 分别校验，不能相互替代，也不跳过证书链或主机名校验。Agent 的配置生成、安装、升级与恢复由 [rss-mdm-agent 服务部署指南](https://dev.azure.com/shengming0923/rss/_git/rss-mdm-agent?path=/docs/guides/local-service-lab.md&version=GBdevelop) 唯一维护。

服务端网关配置服务器证书链和私钥；向客户端交付的信任材料只含公共证书。

本仓开发环境生成的组织 CA 位于 `artifacts/dev-environment/development/ca.crt`；分发此公共文件即可，不分发同目录的 `ca.key`。浏览器控制台的信任仍由浏览器管理，客户端的应用内信任不会修改浏览器。

## 管理员密码恢复

按[Compose 材料导入](operations.md#compose-维护材料与数据库-tls-续期)准备并导入独立 recover.json，沿用初始化配置的 installation、tenant_id 与既有 principal_id；`login` 必须为 null，`password_file` 指向新密码文件，database 使用 mdm_identity_maintenance。该操作轮换密码并撤销旧会话，不创建主体，也不恢复 MDM 业务授权。

```sh
docker compose -p rss-mdm -f /absolute/candidate/deployment/production.compose.yaml run --rm --no-deps --user 10001:10001 --entrypoint /usr/local/bin/rss-mdm-installer init recover-password --config /var/lib/rss-mdm/recover.json
```

配置与秘密为 owner 独占的普通 0600 文件，末级路径不得为符号链接；CA 为可读 PEM。maintenance 密码与恢复文件仅挂入 一次性维护容器，不挂入运行服务。恢复后验证新登录并按受控秘密管理流程处置临时密码文件。

## 运行配置与网络

运行配置从交付的 mdm-config.example.json 填写：实例、租户、产品域名、数据库地址、独立秘密、Windows 公开设备 trust、协议密钥和独立 TLS 输入。各数据库角色连接同一 MDM 数据库。OIDC 可不配置，本地认证无需参考应用或企业 IdP；企业接入使用产品自己的 `/api/v1/identity/oidc/callback`。账户坐标及旧、新主体不自动对应的边界见认证指南。

`identity.audit_worker` 必须配置独立 `mdm_identity_audit` 登录角色及秘密文件；host、port、name 必须与 `identity.database` 一致。安装器通过 Identity 公共 worker 授权接口赋予 consumer 与 Audit 权限，并通过 Ledger 的公开 SQL 接缝赋予追加能力；worker 不具有身份私表、producer、DDL 或直接审计表写权限。运行服务同时挂入 worker 密码，maintenance 密码仍仅归一次性维护命令。现有安装集合新增 `identity-audit-runtime-v1`，旧候选安装账本不会被静默升级。

所有运行模式（含 Apple-only 与 Agent-only）必须配置顶层 `native_protection`，包含 `active_file`、`historical_files` 与 `fingerprint_file`。每个文件恰好包含 32 字节原始随机密钥，权限 0600；不是 hex/Base64/PEM 文本。全新安装分别生成加密钥与比较钥。`active_file` 只用于新密文，最多保留 15 个历史解密钥，按密文中确切 key ID 读取。`fingerprint_file` 维持原有请求、材料与设备比较身份，不能随密文重加密替换。Ledger、Windows 协议保护材料和恢复凭据专用钥集合仍分别保管。旧 `native_protection_key_file` 配置不再接受，也不提供转换入口。

运行配置和 `initialize-authorization` 配置必须显式填写 `audit`：Plain 为 `{"mode":"plain"}`；Ledger 为 `{"mode":"ledger","key_id":"部署提供的标识","key_file":"/run/mdm/audit-key"}`。密钥文件保存至少 32 字节的原始密钥，必须受文件权限保护；服务不自动生成、轮换或在错误时降级。所有运行角色使用 READ COMMITTED，恢复入口拒绝其他隔离级别。

只支持 Nginx 公网网关。gateway 与各租户 server 使用受控主机上的隔离网络；Rust 只保留一个不公开的内部 HTTP 入口。Nginx 终止 TLS/mTLS，覆盖公开 origin、TLS 客户端叶证书和真实来源地址；Rust 先核验实际 TCP peer 等于 `trusted_gateway`，再按通道验证证书用途、撤销、租户和注册。设备路由清除管理会话 Cookie；Windows 原生 Entra 凭据由原生通道验证。

运行配置中的 Windows enrollment/management、Apple management 与 Agent endpoint 只保存公开 `origin`；不再接受设备 listener、TLS 私钥或 PROXY 配置。四类能力可共享域名和端口，也可分开。部署层 `deployment/render_gateway.py` 消费安装工具导出的 `deployment.json`，生成 Nginx HTTPS 路由及 `gateway-ports.compose.yaml`。业务 API 不执行渲染、shell 或容器操作。新增域名必须已包含在网关证书中；新增端口须在部署环境应用生成的 Compose ports override。内部端口固定为 443 与 8443 互换、其它端口同号，不随宿主或入口集合排序改变；维护 `probe_addresses` 使用生成的目标端口。标准初始化从同一映射生成控制台 probe 地址。网关容器的独立网络命名空间设置 `net.ipv4.ip_unprivileged_port_start=0`，允许非 root Nginx 绑定这些端口，不改变宿主设置。

新格式安装后的连接更新使用稳定安装 `instance_id` 与 tenant。先在现有部署设置保存 Agent 首选和候选 HTTPS origins，再由运维修改宿主输入、准备运行文件、运行部署 renderer、应用 Compose 与 Nginx 配置。部署层可用以下命令刷新网关（对应宿主准备必须先完成）：

```sh
docker compose run --rm --no-deps --user 10001:10001 --entrypoint python3 init /usr/local/lib/rss-mdm/render_gateway.py --root /var/lib/rss-mdm/runtime/gateway
docker compose exec -T gateway nginx -t -c /run/gateway/nginx.conf
docker compose exec -T gateway nginx -s reload -c /run/gateway/nginx.conf
```

随后执行原宿主维护观察流程，对每个公开入口进行真实 HTTPS `/readyz` 校验，核对 instance、tenant、host、材料摘要与运行 revision；成功才记录部署观察。`probe_addresses` 可按完整公开 origin 显式给出隔离网络物理探测地址；证书和 Host 始终验证公开身份。控制台发布签名连接配置后，Agent 验签、拒绝回滚并原子保存，回报实际连接地址与安装 revision。

入口轮换采用 `A → A+B → B`。重叠阶段将 B 设为首选，等待设备经 B 回报安装确认后才能退役 A；未确认的活动设备会阻止删除它仍依赖的入口。所有已知入口失联时，管理员从原管理入口下载签名连接文件，在设备通过受保护的离线导入恢复；不得重建注册、密钥、缓存或未决操作。程序更新保留这些状态。Windows/Apple 原生注册 URL 继续由各自原生配置持有，Agent 连接配置不改变其换址机制。

本次只支持新格式全新安装，不接受旧格式双读、升级或迁移。

资源/计划/执行使用当前全新安装结构。产品配置中的 `flow.storage` 持有数据库连接及 target/lineage/epoch，`flow.publication` 持有发布数据库与 sources，`execution.database` 持有执行数据库连接；具体字段以[配置示例](../../fixtures/mdm-config.example.json)为准。旧综合 `management` 和混合 `tasks` 配置不再接受。`content.storage` 显式选择 `volume` 或启用版本控制的 HTTPS `s3`（[S3 配置示例](../../fixtures/mdm-content-s3.example.json)）；PostgreSQL 持有内容控制状态，`content` 配置共享内容仓，`task_signing` 单独配置任务签名；脚本任务要求两者齐备，软件入库/启用不需要任务私钥，原生协议的 `management` 公开 origin 配置保持独立。本版本按全新安装交付，安装清单只持有当前完整 schema。

内容与网关的大小及时间预算必须一致配置。随附 nginx 配置仅为精确上传路由关闭 request buffering，示例正文上限 8GiB；普通请求继续保留 16KiB。管理专属路由的网关上限对应 `management-http/src/body_policy.rs`：Policy/Resource 8MiB、设备 operations 16MiB、PKI rotation/CRL 64MiB、signing recovery 256KiB、Entra policy 128KiB、证书导入及授权规则/用户组 2MiB、软件目录及 Agent 包写入口 1MiB；应用继续按方法执行精确预算与 DTO 校验。内容目录须以可写持久卷提供给服务，签名秘密仍使用独立只读挂载。

## 时间线索引恢复

时间线索引是产品派生数据，`rss_audit` 持久事实仍是唯一来源。当前全新安装包含 `timeline-service-schema-v1`，checkpoint 不持有后台健康状态；旧安装清单不能用于当前候选，启动和安装校验会拒绝不匹配的清单，不提供旧结构自动升级。授权访问设备时间线或管理审计检索时才从 checkpoint 有界追赶，故障返回不可用，后续请求重新尝试。

需要重建时先停止本安装的所有服务实例，由数据库 owner 在一个事务内设置目标租户上下文，删除该租户的 `mdm_timeline.facts`，将其 checkpoint 的 `position`、`source_through` 置为 -1，并为 `generation` 设置新的 UUID。保留既有游标签名秘密和全部 Audit/Ledger 数据，再启动服务并通过授权查询触发追赶。旧游标因世代变化被拒绝；历史追赶完成前，API 明确返回覆盖进度。不得删除 Audit 事实、修补审计回执或改写迁移清单来恢复索引。

安装包含 `certificate-archive-schema-v1`。运行不需要存档主密码；存档通过现有租户授权管理授予独立权限，详见[证书目录](../../crates/certificate-archive-service/README.md)。

## Agent 专用 PKI

缺少 Agent 模板或必填配置的新部署须用当前源码重建候选。配置必须显式包含 `agent_pki`：未启用时使用 `{"mode":"disabled"}`，缺失、旧字段和未知成员拒绝。启用示例：

```json
"agent_pki": {
  "mode": "step_ca",
  "endpoint": {
    "origin": "https://mdm.example.test"
  },
  "trust_file": "/run/pki/agent-trust.json",
  "lifetime": {"mode":"standard"}
}
```

启用 Agent 时，`task_signing` 只引用已持久化权威的 `revision`；私钥由任务签名 owner 加密保管，不再接受 private_key_file、key_id 或 trusted_keys 启动字段。注册 owner 持有独立于任务轮换的受保护配置签名根，以独立签名域签发注册文件和连接配置；安装材料须固定服务身份、tenant 与配置验证公钥。任务密钥轮换不能替换连接配置根。授权期限和平台启用设置只由数据库后台接口持有，旧 `agent_pki.policy` 被拒绝，见 [Agent 接入](../guides/agent-integration.md)。

Agent 证书由统一 step-ca 初始化准备，默认有效期 365 天；Windows 为 90 天。签发者必须覆盖完整证书窗口，剩余不足会拒绝签发。私钥留在设备，产品运行端只取得受限用途凭据，CA 根/中间私钥及管理员凭据不进入运行容器。任务签名仍由原产品 owner 管理，不与设备 CA 混用。

## 设备 PKI 配置

普通部署只维护一套 step-ca。将以下内容保存为输入目录中的 `step-ca.json`，文件引用可以相对于此 JSON；完整字段由 [Settings](../../crates/app/src/setup/providers/step_ca/initialize.rs) 持有。

```json
{
  "origin": "https://step-ca:9000",
  "root_certificate_file": "ca-root.crt",
  "root_crl_file": "ca-root.crl",
  "administrator_certificate_file": "ca-admin.crt",
  "administrator_key_file": "ca-admin.key"
}
```

这四份材料分别是公开 CA 根证书、离线根发布的公开 CRL，以及仅供初始化使用的管理证书和私钥。不提供 CA 根或中间签发私钥。管理员证书的主体和 CA 当前内部地址自动发现，不填写容器 IP。管理证书须有该 CA 的 provisioner 管理权限；根 CRL 由根 CA 运维续发；管理身份续期与根 CRL 更新后沿原文件重跑 `init`。SCEP 解密身份在剩余不足 30 天时由该次初始化自动续期，保留原回调和设备身份。

SIT Compose 已设置 `MDM_STEP_CA_CONFIG=/inputs/step-ca.json`，`init` 等待 CA 健康后执行一次性初始化。使用外置 step-ca 时，在基础 Compose 的 `init.environment` 设置同一变量并提供该文件。内部地址只需能从初始化和服务容器访问；不要求公网解析或宿主 Linux。

首次接入步骤如下；已有部署使用原项目名、卷、秘密和输入目录：

```sh
docker compose --env-file /absolute/sit/compose.env run --rm init
# step-ca 0.30.2 首次增加 SCEP 后需要重新挂载其协议路由；不重新初始化 CA。
docker compose --env-file /absolute/sit/compose.env restart step-ca
docker compose --env-file /absolute/sit/compose.env up -d --force-recreate server gateway
```

重复运行 `ca-init` 复用同一 CA 初始化操作，核验远端 provisioner、模板和原回调身份；不重新生成原密钥或追加配置版本。首次没有运行进程时，配置回执可以处于待观察状态；按前文 `prepare-hosts` 读取实际进程观察，不能把初始化成功当成设备注册成功。

统一初始化自动处理 Agent、Windows、Apple 和可选 Agent bootstrap 所需资源。首次为缺失资源生成受限密钥；已有资源从当前部署材料及认证 CA 管理接口核对、复用。产品内部仍保留各通道授权、证书用途和租户隔离。其他租户由维护命令 `initialize-ca` 指定原 `host_id` 绑定同一份 settings，需要租户回调的资源名称按租户自动隔离；Agent 沿原客户端契约共用受限签发入口，以证书 SAN 和注册授权绑定租户，不覆盖首租户材料。原逐用途准备入口已移除，初始化只使用这一套输入；旧维护记录与材料继续保留。

通道启用时只提供该通道公开 origin 和必要业务材料；公网 TLS 由部署网关统一持有，省略 `providers`、CA `trust_file` 和回调配置。首次启用时按实际 endpoint/management 地址绑定信任，并在同一维护操作内同步尚未使用的 bootstrap 回调，支持非默认公开端口；不把 CA 准备阶段的默认端口当作最终地址。原有已启用通道的协议密钥与信任历史保持不变。Apple 的 APNs/Profile 属于独立业务材料，未提供时只完成 CA 准备，不伪造 Apple MDM 就绪。

### Apple SCEP 与内部 CA 地址

SCEP 是设备向 CA 申请证书的协议，由同一套 step-ca 直接提供。设备地址默认使用当前租户的产品 HTTPS 域名；需要独立入口时只在 `step-ca.json` 设置 `public_scep_origin`。内部 `origin` 与公开入口独立。

同域名时，网关自动生成精确的 SCEP 路径及 `/pkiclient.exe` 兼容路径，只转发 GetCACert、GetCACaps、PKIOperation，验证内部 CA TLS，不转发浏览器 Cookie/Authorization。其余 SCEP 路径与 CA 管理 API 拒绝访问，不发布整个 CA 端口。独立入口由运维设置同样的路径限制。

SCEP 解密身份、模板和 challenge/notify 回调由初始化自动处理，秘密留在 CA 和受保护的维护目录；运行容器只取得原业务所需回调验证凭据。Mac 从描述文件读取自动生成的 SCEP 地址，在本机生成私钥，CA 经产品后端校验本次注册授权后签发。APNs 负责唤醒，Profile 身份负责签名描述文件，均不替代设备 CA。

### 恢复凭据密钥与接收证书

启用恢复凭据时配置顶层 `recovery_credentials`：

```json
{
  "active_key": "recovery-2026",
  "key_files": { "recovery-2026": "/run/mdm/recovery.key" },
  "active_recipient": "接收证书DER的SHA256小写十六进制指纹",
  "recipients": [{
    "certificate_file": "/run/mdm/recovery-recipient.crt",
    "private_key_file": "/run/mdm/recovery-recipient.key"
  }]
}
```

每个密钥文件恰好 32 个随机原始字节，私密文件权限为 0600。凭据密钥、接收 RSA 私钥、现有 native protection 密钥及 APNs/身份密钥分别生成与保管。接收证书和私钥必须匹配，RSA 至少 2048 位。FileVault 使用该证书接收 CMS，Agent 使用其公钥包裹 AES-GCM 数据密钥；不在客户端配置服务端私钥。未配置时不开放恢复凭据接口或派发该类 Agent 任务，macOS 锁定 PIN 托管也不可用。


### Webhook 宿主输入

顶层 `webhooks` 是必填闭合配置，示例中的空 networks 表示没有获准的接收端。
recovery_database 使用独立登录角色，具备 `mdm_webhook_operator` 的能力；按现有角色文件先部署
`webhook-roles.sql`，密码由部署秘密提供，不与访问或投递角色混用。恢复能力不暴露原始 runtime。

Webhook 密钥由 `/api/v1/webhooks/materials` 的领域权威加密持久化，接收端持钥确认后才能激活。安全交付、确认与旧签名退出见[Webhook 材料运维](operations.md#出站-webhook-签名材料)。运行配置不接受 keys/current_file/retiring，修改旧文件不能覆盖数据库材料。

每条 networks 配置包含 tenant、reference、hostname、port、addresses（IP:port）、cidrs 和 ca_files。
所有地址端口须匹配，地址须全部在允许 CIDR 内；CA 为 PEM。首版 DNS 策略为宿主固定地址快照，
adapter 按批准 IP 连接并验证原 hostname；地址变更需更新配置并重启。可显式允许企业内网。
不接受 URL 凭据、query、fragment，不跟随重定向或使用环境代理。

这些配置只描述允许范围；管理员仍须创建并明确启用订阅。访问池的 storage target、lineage 和
execution epoch 来自原宿主配置，在连接建立时固定；源事件复用 RSS 正式 SQL Outbox append 与
原 Audit 事务原子提交，失败不会触发事务后的直接 HTTP。新增组件迁移由既有 installer 执行。

### 固定候选的完整安装资格

`python3 hack/candidate_installation.py /absolute/candidate` 使用普通 Compose 和空库运行正式初始化，只覆盖必要链路：幂等种子、独立管理员真实认证与授权、第二租户及隔离、Compose 直接持有服务。删除部署控制器的重启、动态编排及 Docker 策略测试。数据库/密钥/内容恢复仍由对应 T2 和受控运维演练分别验证；不使用开发 fixture 冒充正式初始化。

只有验证与清理都完成才发布 `installation-result.json`，绑定候选/Compose 摘要，并分别记录执行客户端 OS/架构、Docker daemon OS/架构和系统说明、容器目标平台及 daemon 与容器架构是否相同。客户端可能连接远程 Docker，架构相同也不能独立证明物理宿主原生运行；验收人员补充实际宿主和仿真方式。arm64 与 amd64 候选分别运行；仿真、原生及不同宿主的结果分别记录，不能由一台 Mac 推导所有宿主均通过。协议 `candidate_smoke.py` 的合法预置仅证明相应协议接缝，不是本入口的完整初始化证据。浏览器与真机 T3 按各自输入继续，不能用安装、readiness 或 smoke 代替终端效果。

Native 保护轮换重加密运行凭据及 Apple 的 ADE、账户开通、设备令牌、命令和 DDM 证据行，不修改逻辑版本或重放 MAC。不可变内容对象、已有执行快照、证书归档以及历史备份仍可能依赖旧读取钥；因此本入口保留旧钥，未提供可绕过这些保留条件的删除动作。历史读取钥最多 15 份，达到上限会明确拒绝继续轮换，须完成对应历史数据和备份退出后再处理，不能删除旧钥冒充完成。

当前冷备/恢复操作要求部署侧 PostgreSQL 管理员为 superuser，并在停宿主或撤销 CONNECT 之前检查；该连接只交给离线部署操作员。它用于停写后重新连接、检查全部会话和原角色恢复，不能下发给业务服务。普通运行账户仍保持既有最小权限。

`configure-host channels` 不允许删除已经建立身份的 Windows/Apple 配置，避免重新启用时更换固定 fingerprint 或 identity seed。未配置通道可保持关闭；已配置材料过期或撤销时由领域运行校验降为不可用，更新仍沿原身份进行。

## 真机验收清单与证据

本节提供部署后的执行清单，不是自动判定器或已通过记录。正式 T3 的需求及稳定编号以 [PRD 产品验收](../product/rss-mdm-prd.md)第 10 节为准，独立任务先冻结本轮发布能力、必要场景、真实设备矩阵及故障范围。安装资格、readiness、协议 smoke、浏览器合成数据和已有 T2 均不能替代真实终端效果；不要求每个文档 PR 执行完整真机矩阵。

### 输入就绪与范围冻结

- 保存候选 manifest 摘要、后端/UI/Agent 制品实际镜像或包摘要、依赖 lock 和实际镜像身份、实际宿主 OS/CPU、容器 OS/架构、原生或仿真方式及 Docker/Compose 版本。含控制台的验收必须使用真实 MDM 前端；Agent 包提供匹配 wire 和信任材料；后台允许未签名、ad-hoc 或未公证的包，真实签名与公证状态如实记录，安装许可由目标系统处理。
- 从设备网络检查域名、公开端口、TLS 完整链、主机名及设备时间；从实际服务身份检查 PostgreSQL/RustFS/CA TLS、权限、持久目录与可恢复空间。容器内部可达不代表设备可达，不使用跳过证书验证的参数。
- 按所选能力提供真实 APNs/Profile、ABM/ASM/Entra/IdP 等组织资格和受控签名材料；CA 模板与回调由上述统一初始化准备，根 CRL 沿原输入更新。冻结设备 OS edition/build、架构、注册方式、用户/系统执行身份、浏览器及 Agent 版本；不从一次注册推断所有平台或权限组合可用。
- 准备平台管理员、独立业务管理员、只读/受限账户及合法第二租户宿主；通过领域 API 发布测试资源、软件版本、Group/Scope/Policy。安装器不制造业务成功数据，跨租户场景不能只修改请求中的 tenant。
- Windows/macOS 的服务、桌面/helper 及 PowerShell、osquery、Node/worker 等运行依赖按实际 Agent 包和所选动作准备；它们属于端侧，不能误列为服务器常驻容器。
- 每项能力在开测前明确 required 或 excluded，写明需求编号与理由；缺组织资格、设备或实现时对必选项记 blocked/unknown，不以临时改为 excluded 获得通过。输入变化开新轮次并重测受影响项。

### 真实闭环与反例

| 验收域 | 必须观察的结果与边界 |
|---|---|
| 入口与会话 | 设备网络上的真实页面、登录/刷新/退出、Cookie/CSRF；只读/无权限账户拒绝且无业务副作用 |
| 安装与租户开通 | 独立平台/首业务身份和合法宿主；第二租户完整开通；失败或容量不足沿原操作恢复，跨租户数据、操作与对象前缀均被拒绝 |
| Windows 原生 | 真实注册、设备证书及认证签入、原生采集进入产品资产；至少一项本轮支持的配置/命令有终端效果 |
| Apple 原生 | Profile 签名、SCEP challenge/notify、mTLS Authenticate/TokenUpdate、APNs 唤醒以及 Mac 上的命令/采集效果 |
| Agent Windows/macOS | 各平台真实签名包安装、登记与证书激活、采集报告、任务信任 ACK、签名任务领取/执行/结果与终端效果；重启后信任与身份持续有效 |
| 软件与对象存储 | 上传/冻结版本、RustFS 确切对象版本及摘要、设备下载/安装/版本检测；重启后原版本仍可读，错误摘要和被撤销凭据明确失败 |
| 内容边界 | 按本轮支持范围验证 Range、分块/多段上传、重放和内容完整性；失败不发布半成品，租户前缀之外访问被拒绝 |
| 策略与资产闭环 | Group/Scope/Policy、三类采集和合规按需求产生分配、设备效果及投影；旧结果/空值/来源冲突不误覆盖或误删，不把服务端入队当作设备完成 |
| 跨通道与结果未知 | MDM 与 Agent 的重复副作用保护；超时、断网、晚到结果和重启沿原身份恢复，未知操作不自动换 ID 或双发 |
| CA 与撤销 | 各用途模板/期限/凭据正确，跨用途证书不能取得设备身份；撤销持久生效并在签名 CRL 实际发布，既有 TLS/恢复会话仍受当前凭据校验 |
| 共享 CA 专项 | 在同一套 CA 上分别验证三用途签发、SCEP/JWK、共享 CRL 传播、单用途撤销与其它合法用途继续工作；保留同一物理 CA 上的实际结果 |
| 故障与联合恢复 | 服务/宿主重启、PG/CA/RustFS 不可用、原操作续跑及同址冷恢复；原账户、设备凭据、密钥、对象版本和审计关联可核验，见[单机恢复边界](operations.md#单机部署的重启与恢复边界) |

### 按发布能力补齐的外部条件

| 能力 | 真实输入与追加验证 |
|---|---|
| OIDC / Windows Entra | 真实 issuer/组织、批准的回跳与网络；宿主准入由部署方配置，租户 provider/Entra policy 经领域 API；验证认证、权限映射和对端故障 |
| WNS | 真实 PFN/SID/secret 经 WNS API 校验和宿主应用，验证设备实际唤醒；OAuth 成功或轮询成功不能代替推送效果 |
| ADE / Managed Apple Account | 真实 ABM/ASM 组织、设备资格、token/映射和账户签名材料，经组织/材料 API；验证真实注册、到期及恢复，合成 fixture 不替代组织资格 |
| MDM→Agent / Agent→MDM | 已签名 Agent 包、bootstrap 用途 trust/provider/webhook 与真实注册入口；验证原生安装/系统确认、引导交换、激活与清理，opened 不等于注册完成 |
| WinGet / Brew 私有发布 | 受控来源、仓库/产物、访问身份及具备相应执行能力的实际 Agent 包；按声明验证原生源、架构/上下文和安装检测，直接下载不能冒充原生源已验证 |
| 恢复凭据 / Ledger / 证书存档 | 对应密钥、接收证书及授权；真机分别证明 BitLocker/FileVault/Recovery Lock 等选定恢复动作；Ledger 使用原安装密钥核验历史；存档不能替代 APNs/Profile 运行材料 |
| SMTP / Webhook | 经批准 profile/目标及真实对端凭据；核对 TLS、权限、实际投递/签名确认、失败和未知结果；不将资格消息接受视为收件箱或业务处理完成 |

### 每轮记录与结论

在源码仓外的受控验收目录保存 run-id、UTC 开始/结束时间、输入摘要、范围及设备矩阵。每项记录需求/场景、required/excluded 及理由、预期/实际、结果、操作者、tenant/device/registration、原 operation/request ID 和脱敏证据路径。初始结果为 not_run；执行后区分 passed、failed、blocked、unknown，未知或缺依赖不能填成 passed。

保存产品审计关联、设备侧观测、必要截图和真实制品摘要；不收集密码、Cookie/token、私钥或恢复秘密。ACK、APNs 200、上传成功和健康探针只证明各自阶段。失败保留原操作与诊断，修复后开新轮次，不清库、换 CA 或重新注册来覆盖旧失败。

只有本轮必选项均有实际证据且通过，才能声明确切候选、OS/架构、注册方式、能力和拓扑范围内的结论；共享 CA、同机全部组件和各设备组合分别限定。未选能力、未测组合、HA/容量/性能、异址恢复及未来跨版本升级均不能从该结果推导为支持；升级边界见[版本切换](operations.md#版本切换)。

## 安装遥测存储

遥测为显式可选配置。先以部署管理员执行 `prepare-telemetry --config /absolute/private-request.json`，再通过 `configure-host` 的 `telemetry` 变更启用。请求结构由 `setup::providers::telemetry::Request` 持有，运行结构由 `telemetry::Config` 持有；安装请求、操作 UUID、私有安装目录与回执一起保管。重复执行使用原请求，变更同一 UUID 的内容会冲突。

遥测数据库与产品主库分开。PostgreSQL 模式在安装请求中显式提供 UTC 微秒分区边界；Timescale 模式先由部署方安装要求的扩展版本。dedicated 模式为每个租户配置独立数据库、运行角色、维护登录与池，维护登录只能切换到该库的 NOLOGIN owner。运行启动只做准入，不创建对象，不自动选择或回退存储模式。支持版本与预算由安装器及固定 RSS adapter 校验，不能用“能连接”替代准入结果。

ClickHouse 使用固定 HTTPS origin 和显式 CA，运行读、写、维护及部署管理员凭据分离。部署安装账户须获准使用 named collection（XML 管理账户显式启用 `named_collection_control`）；运行账户不继承安装权限。部署方须提供固定的 `rss_ts_ch_guard` named collection，连接对应 PG 控制库并验证 TLS；不得把控制库替换为产品主库。原生备份使用名为 `mdm_backup` 的本地磁盘，挂载目录须与请求的 `backup_directory` 一致，`server_configuration_files` 列出实际配置、named collection 和 libpq 信任材料。安装器验证服务版本、账户权限和实际 adapter，配置缺失时拒绝启用。

分区准备及 dedicated 原生列存转换使用 `maintain-telemetry-storage`，传入原安装请求和固定维护操作 UUID。操作要求停写，并核对原安装身份；返回 `more` 时沿用原请求继续，`unknown` 时不得生成新操作身份。该入口不提供在线后端迁移。

共享 ClickHouse 安装增加租户时，使用 `prepare-telemetry-tenant` 提供原安装请求、新操作 UUID、租户身份、独立 reader 凭据及游标密钥。该入口核对原安装身份，为新 reader 建立精确租户行策略，并在实际准入后返回该租户的运行配置。不得复用另一租户的 reader 或把新租户伪装成首次安装。联合备份须同时包含所有使用该安装的宿主配置和凭据。

主业务库、普通遥测 PostgreSQL 和 Timescale profile 统一采用 PG17；普通 PostgreSQL 共用 `postgres` 固定镜像，Timescale 固定为 `2.30.2-pg17`。联合备份统一由安装器携带的 PG17 `pg_dump`/`pg_restore` 执行。缺少或不匹配的客户端明确失败。ClickHouse 的备份磁盘和配置恢复仍遵循原 UID/GID 与权限约束，部署时应使其与恢复执行身份兼容，不能依靠恢复命令隐式 chown。

首个启用遥测的宿主会在产品控制库登记该租户的存储安装身份、接收限额、存储保证和游标密钥摘要。后续副本必须匹配，不能通过增加副本、换一份配置或在原地址新建空库把已接收工作转移到另一个后端。接收速率在租户内共享；待交付批次数仍按注册身份限制。当前安装的这些保证固定不变，只有本地连接池规模可独立调整；Profile 内的较低预算仍可按业务版本发布。恢复须同时恢复产品控制库和对应存储安装身份。

当前开发基线的自有布局直接替换；不提供历史库迁移或兼容 reader。已有开发数据库、凭据和
journal 必须保留：新布局使用新建实例，不能修改旧安装账本的版本或摘要来绕过检查。
同一当前制品的重复安装、失败恢复及权限检查仍须成立。

## 新租户默认基线

当前格式仅支持全新安装。首装和后续新租户在真实账户及授权创建后保存一次基线意图，服务启动后按稳定操作身份恢复；不对历史部署补种。后端唯一声明默认值，初始化后均为普通可管理对象：全部受管设备、Windows、macOS 三个系统组；平台 Scope；身份、OS、硬件、软件蓝图及每小时采集策略；性能模板、字段、保留策略与 Profile。

系统组允许改名称、描述、重算及在解除引用后删除，成员与平台选择器由注册生命周期维护。未采集资产的已注册设备也可入组；平台冲突不进入平台专属组。普通 Scope 和自定义策略继续使用原 Group 引用及现有排除、限制与执行防重。

性能默认每 60 秒采样、5 分钟上传，同时投影当前值和历史；原始保留 7 天、汇总 30 天，恢复及补传窗口各 24 小时。预算为 4096 points、1 MiB、128 resources、执行 10 秒、输出 256 KiB，文件系统最多 64 项。仅发布 CPU busy%、内存 total/available、文件系统 total/free；不默认启用 boost、用户活动、SMART 或网络速率。MDM-only 通道不支持 Agent 遥测。

每个宿主使用自身 `deployment.content_volume`；未显式设置时使用该宿主 `deployment.directory/content`。运行配置与冷备份、恢复校验同一内容位置；共用存储时在各宿主显式声明相同卷路径。

标准安装自动准备独立 PostgreSQL 遥测数据库、受限 runtime 角色和持久内容卷。Compose 的 `content` 卷由初始化进程和服务共用，内容键按租户隔离；供应方管理凭据保存在安装状态卷，业务服务没有 DDL 权限。保留安装目录及其中的遥测请求、密钥和回执，恢复使用原材料，不能重新生成后冒充原安装。

运行诊断的 `initialization` 分量区分资产待配置、遥测待配置和依赖阻塞；`configured` 只表示配置发布完成，设备是否产出数据应查看 CollectionRun、Observation、Inventory 和遥测历史。完成步骤不会因对象被编辑、禁用或删除而重建；未完成步骤若遇到 CAS 冲突，应按原对象和操作回执诊断，不能强制覆盖管理员变更。授权被撤销时恢复必须重新验证原授权依据，不能替换成服务管理员。

设备指标（CPU、内存）与文件系统分别发布普通采样模板和 Profile，保持每个 Profile 的 128 resources 预算，同时完整支持最多 64 个文件系统；两类均采用 60 秒采样、5 分钟上传及当前值/历史双投影，可通过普通资源和策略分别管理。
