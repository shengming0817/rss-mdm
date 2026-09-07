# WinMDM 历史参考

本地目录 `winmdm20260220-develop/` 保存历史代码参考，已通过仓库 `.gitignore` 忽略；代码、历史配置和归档大文件不随 Git 提交。克隆仓库后该目录不会自动出现。

## 来源

- 归档：`winmdm20260220-develop.zip`。
- SHA-256：`bb08749e671080dd96a3d61dd31c662730604cd288303fa67e7917aaf9778e67`，与原始 PRD 中记录一致。
- 完整解压文件数：3,481；总大小：153,005,820 字节（不含目录）。
- PRD 来源：`WinMDM_PRD_v0.2_跨平台统一管理_20260907.md`。
- 原始 PRD SHA-256：`d10b3cbb471ef221ce54fbe3c47af0dce163a39ebda1a17a64fc0791732985d7`。

清理后的产品需求见 [当前 PRD](../docs/product/rss-mdm-prd.md)。原文件摘要仅标识导入来源，不用于校验持续维护的 PRD。

## 本地恢复

取得上述归档并校验 SHA-256 后，在仓库根目录执行：

```sh
unzip /path/to/winmdm20260220-develop.zip -d reference/
/usr/bin/git check-ignore -v reference/winmdm20260220-develop/
```

原 ZIP 保留，清理不修改来源归档。

## 使用边界

历史代码用于查阅实现与来源证据，不是本仓库当前实现，也不代表远端最新状态。本次没有运行历史系统或验证其功能。

历史快照内部的 `AGENTS.md`、`CLAUDE.md` 和旧 CI/部署配置属于原项目材料，不作为 rss-mdm 的仓库级规则。历史路径与编号在 [来源索引](../docs/reference/historical-sources.md) 中维护；历史实现判断和旧规划见 [历史基线](../docs/reference/winmdm-baseline.md)。
