# 应急权限迁移与最短冲突回溯

维护方要把**合成值班账号**迁移到新团队。迁移窗口期新旧租户策略同时有效，
授权链（`auth`）与职责互斥约束（`sod`）各自按独立的**有效水位（water-mark）**
更新。给定目标变更，本项目用 **原生 Windows + Python 3.12 标准库**实现一套
**离线权限证明**：

- 找**最少的应急例外集合**，既覆盖全部关键资源，又不违反职责互斥（SoD）；
- 报告每个关键权限**所有保留的独立授权来源**；
- 同成本时按**固定 ID 顺序**给出可独立复核的规范化证书；
- 晚到的撤销会改变“当前建议”，但**绝不重写已封存版本**（哈希链 + 只读 + 拒写）；
- 小规模用 **`2**k` 全子集独立枚举**作为预言机，覆盖三类边界：
  同一控制人担任两角色、继承拒绝覆盖、含真实根 / 无根的环；
- 在**恰好 60,000 条角色边**的数据上跟踪**一次资源侧规则变更**，
  核对重算分量数，并保证增量跟踪与全量重算**完全一致**。

无第三方依赖、无网络、无外发数据；所有数据均为确定性本地合成数据。

---

## 一键运行（原生 Windows / Python 3.12）

在本目录（含 `run.py`）打开 `cmd` / PowerShell：

```bat
python run.py
```

成功时退出码为 `0`，并生成：

```
VERIFICATION_REPORT.md                 # 人读总报告（根目录，运行时重生成）
artifacts\
  verification_report.json             # 机读全部检查结果
  certificates\*.cert.json             # 每个小场景 + 迁移 v1/v2 的证书
  scale60k.report.json                 # 60k 规模 / 一致性报告
  sealed\
    SEAL-0001.json                     # 撤销前已封存版本（只读）
    SEAL-0002.json                     # 撤销后当前建议的新封存版本（哈希链接 SEAL-0001）
    ledger.jsonl                       # 只追加封存台账（含封存时文件字节哈希）
```

其它入口：

```bat
python -m permission_proof selftest                       # unittest 套件
python -m permission_proof scale                          # 只跑 60k 检查
python -m permission_proof verify artifacts\sealed\SEAL-0001.json
python -m permission_proof verify artifacts\certificates\CERT-MIG-V1.json
```

> 控制台已统一 `reconfigure(encoding="utf-8", errors="replace")`，
> 在 cp936 控制台下也不会因符号/中文崩溃；报告以 UTF-8 写文件。

---

## 题面条款 → 实现 / 校验位置

| 题面要求 | 实现 | 关键校验 |
|---|---|---|
| 原生 Windows、Py3.12、标准库、离线 | 全包仅 `json/hashlib/dataclasses/collections/...` | `environment` 检查；无 import 第三方 |
| 新旧租户策略并存、各自有效水位 | `permission_proof/store.py` `PolicyLog`，键 `"<tenant>:<auth|sod>"` | `watermarks` 段；`WatermarkTests` |
| 授权链 / SoD 随各自水位更新 | 事件 `add/revoke` 带每键单调 `wm`，`fold(vector)` 只取 `wm<=effective` | `test_late_revocation_hidden_until_watermark_advances` |
| 最少应急例外 + 覆盖关键资源 + 不违反 SoD | `exceptions.py` `solve_min_exceptions` / `enumerate_exception_sets` | 每个场景的 `optimum_*`、`canonical_*` 检查 |
| 报告所有保留的独立来源 | `evaluate.py` 允许票的 entitlement 源 + 独立 assignment 锚点源；证书 `all_retained_sources` / 每资源 `retained_sources` | `all_retained_sources_exact`、`per_resource_retained_sources_exact` |
| 同成本按固定顺序给可复核证书 | 固定字典序；最小基数 + 同基数字典序最小；`certificate.py` 重枚举复核 | `chosen_is_canonical_minimum`、`solver_agrees_with_enumeration` |
| 晚到撤销改变当下建议 | 迁移剧：撤销旧租户值班分配，最优 `[M02]`(1) → `[M01,M02]`(2) | `late_revocation_changes_current_recommendation` |
| 不能重写已封存版本 | `seal.py` 哈希链、写一次、`ImmutableSealError`、Windows 只读位、台账字节哈希 | `sealed_v1_file_hash_unchanged`、`same_version_rewrite_refused`、`tampered_envelope_rejected` |
| 同控制人担任两角色 | `scenarios.controller_dual_role_scenario`；SoD 聚合到 controller | `controller_level_detects_dual_role_conflict` + 朴素单账号检查漏报对照 |
| 继承拒绝覆盖 | `inherited_deny_scenario`；优先级 break-glass > policy deny(含继承) > allow | `deny_override_precedence`、普通 allow 子集不可行 |
| 环里有真实根 / 无根 | `graph.classify_role_cycles`（迭代 Kosaraju + 逆 BFS 找授权根） | `cycle_root_classification` 两个夹具 |
| 6 万角色边 + 一次资源侧规则变更 | `scale60k.py`，种子 `16396`，恰 60000 唯一有向边 | `exactly_60000_role_edges` 等 |
| 核对重算分量数 | DSU 与 BFS 双实现；`TrackedComponents` 受影响分量局部重算 | WCC 40；合并图 40→39；split 用例 2→3 |
| 全量一致性 | 增量分区 == 全量 BFS == DSU（按节点划分比较，与标号无关） | `v2_tracker_partition_matches_full_bfs`、`v2_dsu_partition_matches_bfs` |

另有 **200 个确定性随机小实例**（最多 8 候选 → 每实例全子集枚举）交叉核对
“全子集预言机的固定顺序赢家”与“定序求解器”完全一致。

---

## 权限与冲突语义（可复核的形式化约定）

- 边 `child -> parent` 表示子角色**继承**父角色权限；闭包用带 visited 的栈求，环安全。
- 决策优先级（`evaluate.py`）：
  1. **break-glass allow**（候选显式 `overrides_deny=true` 的应急来源）最高；
  2. 否则任一 **policy deny**（直接或经继承获得，含资源侧拒绝）→ `deny`，
     覆盖所有 allow —— 即“**继承拒绝覆盖**”；
  3. 否则任一 allow → `allow`；否则 `none`（隐式拒绝）。
- **独立来源**分两类并集上报：
  - `entitlement_sources`：实际生效的 allow / break-glass 规则来源（`SRC:*`、资源侧 `RR*`、应急 `EXC-*`）；
  - `anchor_sources`：把主体锚到该规则持有角色的**每一条独立 assignment 来源**（`ASG:*`）。
  证书还为每个来源给出确定性最短继承路径 `inheritance_path` 与锚点列表。
- SoD 在 **controller（控制人）粒度**判定：聚合该控制人名下所有账号的角色闭包，
  再检查每个互斥角色对。单账号粒度的“朴素检查”结果会作为对照保留，
  用来证明“同一控制人通过两个账号分饰两角”只有控制人粒度能发现。
- **真实根 vs 无根环**：角色上直接声明了有效授权规则（或被显式指定为
  `authority_root_roles`）即“真实授权根种子”。用 SCC 找环；环内含种子即
  “环里存在真实根”，环及其可达集合都碰不到种子即“无根环”，无根环不产生任何独立来源。

### 固定顺序与最优性

候选按 ID 字典序固定排序。求解器按基数 `0..k`、同基数用
`itertools.combinations` 的字典序扫描，**第一个可行集**即：
基数最小 ⇒ 同成本 ⇒ 排序后 ID 向量字典序最小。验证器不信任证书结论位，
而是从内嵌 `world_snapshot` 重新 `2**k` 全枚举来复核“最少 + 规范赢家 + 来源 + SoD”。

### 封存与晚到撤销

`SEAL-0001` 内嵌当时的有效策略快照与水位向量，故可脱离当前日志独立复核；
信封提交 `cert_hash`，并以 `prev_hash` 串成 SHA-256 链。晚到撤销以更高水位事件
追加（在推进 `old:auth` 水位前甚至不可见），推进后当前建议改变并封存为
`SEAL-0002`；`SEAL-0001` 的文件字节哈希保持不变、仍按其历史快照有效。
任何对信封/证书的篡改都会使摘要或重算复核失败（报告含 `tamper_probe` 结果）。

---

## 确定性的预期结果（由断言守护）

小规模：

| 场景 | 候选 | 全枚举子集 | 最少 | 规范选择 |
|---|---:|---:|---:|---|
| S1 同控制人两角色 | 3 | 8 | 1 | `EXC-S1-20-payops-role`（同成本另有 `EXC-S1-30-direct-perm`；`EXC-S1-10` 触发 SoD 被否） |
| S2 继承拒绝覆盖 | 3 | 8 | 1 | `EXC-S2-20-breakglass-a`（同成本另有 `EXC-S2-30-breakglass-b`；普通 `EXC-S2-10` 仍被拒） |
| S3a 环含真实根 | 1 | 2 | 0 | `[]`（环内 `cyc.b` 带真实授权，已覆盖） |
| S3b 无根环 | 2 | 4 | 1 | `EXC-S3B-20-real-grant`（`EXC-S3B-10` 重复无根角色无授权） |

迁移：水位 v1 下当前选择 `["EXC-M02-window-bg"]`（1 个）；撤销旧租户值班分配、
仅推进 `old:auth` 后，v2 当前选择 `["EXC-M01-obs-scoped","EXC-M02-window-bg"]`（2 个）。

60k（种子 `16396`）：恰好 60,000 条唯一角色边、16,000 个角色、按构造 40 个弱连通分量；
一次 `RR-TRACK` 资源目标从 `res.only_a` 改到 `res.bridge` 的规则变更，
在合并“角色—资源”图上恰好合并两个分量：**40 → 39**；增量、全量 BFS、DSU 三方分区一致。
SCC 数与含环 SCC 数由实际重算写入报告（随机加边会产生大量环，故不写死其数值，只校验结构正确性）。

---

## 目录结构

```
run.py                         # 一键端到端：生成 artifacts + VERIFICATION_REPORT.md，返回退出码
permission_proof/
  canon.py                     # 规范化 JSON / SHA-256 / 固定排序
  graph.py                     # DSU、BFS 分量、迭代 Kosaraju SCC、环根分类、受影响分量跟踪
  world.py                     # 有效策略快照读模型 + 例外合并
  store.py                     # 多租户、多流、水位化只追加事件日志
  evaluate.py                  # 拒绝覆盖决策、独立来源/继承路径、控制人级 SoD
  exceptions.py                # 2**k 枚举预言机 + 最小基数/定序求解器
  certificate.py               # 证书构造与“从快照重枚举”独立验证
  seal.py                      # 哈希链写一次封存 / 台账 / 篡改探针
  scenarios.py                 # 四个小夹具 + 迁移日志与晚到撤销
  scale60k.py                  # 60k 确定性数据 + 一次资源侧变更 + 全量一致性
  verify_all.py                # 全部检查、报告与 Markdown 渲染
  cli.py / __main__.py         # all | scale | verify | selftest
tests/test_proof.py            # unittest 套件
```

## 说明 / 边界

- 这是**防御性、离线、合成数据**的权限与职责冲突验证工件；不含任何真实账号、密钥或外网调用。
- “应急例外”被建模为可审计的临时授权来源；break-glass 之所以能压过继承拒绝，
  是显式建模的更高优先级应急层，且同样进入 SoD 与证书复核，并非绕过审计。
- 异常集合优化在小规模下做精确全枚举（题意明确要求小规模独立枚举）；
  60k 规模用于图分量 / 增量一致性，不用于枚举例外。
