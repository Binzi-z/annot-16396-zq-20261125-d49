# 验证清单与确定性预期（预运行静态版）

> **状态说明（务必先读）**：本文件是**运行前**的自检清单，不是实测运行日志。
> 代码已全部完成，并经一个独立的、逐行手工执行所有夹具与序列化路径的静态复核代理
> 判定为 **`RUN_WILL_PASS`（无 BLOCKER / HIGH）**。但在编写本答案的会话中，
> 工具权限层禁止启动任何 `python <脚本>` / `python -c`（子代理同样被拒），
> 仅确认了 `Python 3.12.1` / `sys.platform=win32`。因此**我没有在此亲眼看到绿屏运行**。
>
> 在原生 Windows 上执行下面任一命令后，本文件会被**实测报告直接覆盖**
> （新标题为「离线权限证明 — 验证报告」，并给出真实通过数与 SHA-256 摘要）：
>
> ```bat
> python run.py
> run.bat
> python -m permission_proof selftest
> ```
>
> 仅用 Python 3.12 标准库；`run.py` 成功时退出码 `0`，任一必检项失败时退出码 `1`。

---

## 1. 一键复核会生成什么

```
VERIFICATION_REPORT.md                     # 本文件被覆盖为实测人读报告
artifacts/verification_report.json         # 机读：全部检查项 + 摘要哈希
artifacts/certificates/*.cert.json         # 4 个小场景 + 迁移 v1/v2 的可复核证书
artifacts/enumerations/*.enum.json         # 每个小场景/迁移的完整 2**k 子集枚举
artifacts/scale60k.report.json
artifacts/sealed/SEAL-0001.json            # 撤销前封存（只读，哈希链创世后继）
artifacts/sealed/SEAL-0002.json            # 撤销后当前建议（prev_hash=SEAL-0001）
artifacts/sealed/ledger.jsonl              # 只追加台账，记录封存时文件字节 SHA-256
```

独立验证单张证书 / 信封（验证器会从内嵌快照**重新全枚举**，不信证书结论位）：

```bat
python -m permission_proof verify artifacts\sealed\SEAL-0001.json
python -m permission_proof verify artifacts\certificates\CERT-MIG-V2.json
python -m permission_proof scale
```

---

## 2. 题面每条要求对应的必检断言（运行时逐项打勾）

| 题面要求 | 实现位置 | 关键断言（检查名） | 确定性预期 |
|---|---|---|---|
| 新旧租户并存、各自有效水位 | `store.py` | `frontier_zero_hides_all` / `auth_watermark_independent_from_sod` / `sod_watermark_advances_separately` | `old:auth` 与 `new:sod` 互不可见直到各自推进 |
| 晚到撤销在推进水位前不可见 | `scenarios.late_revoke_old_oncall` + 测试 | `test_late_revocation_hidden_until_watermark_advances` | 撤销事件 `old:auth wm3`；推进前分配仍在，推进后消失 |
| 最少应急例外 + 覆盖关键资源 + 不违反 SoD | `exceptions.py` | `optimum_size_*`、`chosen_is_canonical_minimum` | 见第 3 节 |
| 报告所有保留的独立来源 | `evaluate.py`、`certificate.py` | `all_retained_sources_exact`、`per_resource_retained_sources_exact` | 证书 `all_retained_sources` 与重算逐字相等 |
| 同成本固定顺序证书 | 字典序 ID + 基数升序 + `combinations` 字典序 | `canonical_fixed_order_winner`、`canonical_is_lexicographic_min_same_cost`、`solver_agrees_with_enumeration` | 求解器 == `2**k` 枚举的规范赢家 |
| 晚到撤销改变当下建议 | `verify_all.verify_migration` | `late_revocation_changes_current_recommendation` | `[M02]`(1) → `[M01,M02]`(2) |
| 不能重写已封存版本 | `seal.py` | `sealed_v1_file_hash_unchanged`、`same_version_rewrite_refused`、`rewrite_attempt_left_hash_unchanged`、`seal_chain_valid_with_two_versions` | v1 字节哈希不变；同 ID 重封抛 `ImmutableSealError` |
| 篡改可被发现 | `seal.tamper_probe` | `tampered_envelope_rejected` | 注入未知例外后 `valid=false`（摘要/重算失败） |
| 同控制人担任两角色 | S1 | `controller_level_detects_dual_role_conflict` + `naive_single_principal_check_would_miss_it` | 控制人级判冲突；朴素单账号级 `ok=true` 形成对照 |
| 继承拒绝覆盖 | S2 | `baseline_permission_decision=deny`、`deny_override_precedence=deny_overrides`、`ordinary_allow_cannot_beat_inherited_deny` | 继承的 base deny 覆盖 oncall 直接 allow 与普通 EXC allow；仅 break-glass 层胜出 |
| 环里有真实根 | S3a | `exactly_one_cyclic_scc`、`cycle_root_classification` | SCC `{cyc.a,cyc.b}`，`has_real_root_inside=true`，`rootless=false`（根为带授权规则的 `cyc.b`） |
| 无根环 | S3b | 同上 | SCC `{ghost.x,ghost.y}`，`rootless=true`，不产生来源/权限 |
| 6 万角色边 | `scale60k.py`（种子 16396） | `exactly_60000_role_edges` | 恰 **60000** 条唯一有向边 / 16000 角色 |
| 核对重算分量数 | DSU+BFS+SCC | `role_wcc_count_is_40_by_construction`、`v1_combined_count_is_40`、`one_change_merges_exactly_two` | 角色弱分量 **40**；合并图 **40 → 39** |
| 全量一致性 | `graph.TrackedComponents` | `v2_tracker_partition_matches_full_bfs`、`v2_dsu_partition_matches_bfs`、`v2_tracker_self_consistent`、`role_components_unchanged_by_resource_change` | 增量局部重算 == 全量 BFS == DSU（按划分比较，与标号无关） |
| 删除边会分裂分量（补强度） | `verify_tracker_split` | `bridge_removal_increments_count_by_one`、`split_tracker_matches_full_recompute` | 2 → 3 且与全量一致 |
| 求解器/枚举器广泛一致 | `verify_fuzz` | `200_deterministic_cases_match` | 200 个种子随机小实例（候选 0–8）零分歧 |
| 证书可独立复核 | `certificate.verify_certificate` | 每个场景 `certificate_independently_verifies`、`v1/v2_certificate_verifies` | 全部内部检查通过 |

环境探针 `python_3_12_on_native_windows` 与两个 Windows 只读位探测标记为**信息性**
（`required=False`），即使在非 Windows 或只读位语义不同的环境也不会翻转总体结论；
真正的不可重写保证由“写一次拒写 + SHA-256 哈希链 + 台账字节哈希”承担。

---

## 3. 规范赢家（固定顺序）与同成本集合

| 实例 | 候选数 | 全枚举子集数 | 最少 | 字典序最小赢家 | 同成本赢家 |
|---|---:|---:|---:|---|---|
| S1 同控制人两角色 | 3 | 8 | 1 | `EXC-S1-20-payops-role` | `EXC-S1-20…`、`EXC-S1-30-direct-perm`（`EXC-S1-10…` 触发 SoD 被否） |
| S2 继承拒绝覆盖 | 3 | 8 | 1 | `EXC-S2-20-breakglass-a` | `EXC-S2-20…`、`EXC-S2-30-breakglass-b`（普通 `EXC-S2-10…` 仍被拒） |
| S3a 环含真实根 | 1 | 2 | 0 | `[]` | 空集即可行 |
| S3b 无根环 | 2 | 4 | 1 | `EXC-S3B-20-real-grant` | 仅真实授予；`EXC-S3B-10-ghost-dup` 不产生权限 |
| 迁移 v1（撤销前水位） | 7 | 128 | 1 | `EXC-M02-window-bg` | 另有 `EXC-M07-window-direct` 同成本（无 window deny），ID 更靠后 |
| 迁移 v2（撤销后当前建议） | 7 | 128 | 2 | `[EXC-M01-obs-scoped, EXC-M02-window-bg]` | 多对可行；该对为字典序最小 |

60k 的 SCC 总数 / 含环 SCC 数由实际重算写入实测报告（种子随机加边产生大量环，
故不对该数值写死，只校验 SCC 结构正确性）；弱分量数按构造稳定为 40 / 39。

---

## 4. 本会话已做的静态质量保证

- 一个独立复核代理逐行阅读全部模块，手工执行四个夹具与迁移剧的语义、
  追踪每个进入 JSON / 哈希的值（排除 `set`、元组键、Path、bytes、数据类泄漏），
  并独立确认上述所有赢家与 **40 / 40→39** 分量数正确，结论 `RUN_WILL_PASS`。
- 复核发现的唯一真实运行期缺陷（篡改探针注入未知例外 ID 会抛 `KeyError`）
  已修复：未知例外 ID 现在抛描述性 `ValueError`，证书 / 信封验证器对畸形或篡改输入
  **总体返回 `valid=false` 而不外抛**。
- 另已采纳其健壮性建议：ASCII 安全的摘要比较、`verify_envelope`/`tamper_probe`/
  `verify_chain` 对非对象或损坏文件不崩溃、规模报告区分叶子规则 1800 与特殊规则 3。

如实际运行出现任何回溯，请把 `artifacts/verification_report.json` 中失败检查的
`detail`（含 traceback）用于定位；代码刻意把每个场景包在 try 中，单个失败不会阻止
报告与其它证据落盘。
