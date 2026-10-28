# DICK CLI（精简版）

基于 [yunli396/Dick](https://github.com/yunli396/Dick) 的命令行精简版，保留跨软件源搜索、安装和常用包管理功能。移除了 Web 界面、远程访问、令牌、证书和网页 AI 翻译；软件源索引与包管理器仍可能需要联网。基于上游提交 `6db89e0`，原项目采用 MIT 许可证，见 [LICENSE](LICENSE)。

## 运行和安装

需要 Python 3.11 或更新版本，运行时仅依赖标准库。从本目录直接运行：

```sh
python -m dick --help
python -m dick source list
python -m dick source scan
python -m dick update --source pacman
python -m dick search firefox
python -m dick install firefox --dry-run
```

也可以从此源码目录安装：

```sh
pipx install .
# 或使用你管理的 Python 虚拟环境：python -m pip install .
```

安装后将上述命令中的 `python -m dick` 换成 `dick`。正式安装软件时去掉 `--dry-run`；程序会调用对应的原生包管理器，可能需要提权。它不会自己构建 AUR 包，需要本机安装 `paru` 或 `yay`。

## 命令

| 命令 | 用途 |
| --- | --- |
| `source list` / `source scan` | 查看支持的来源 / 扫描本机源配置 |
| `source enable` / `source disable` | 启用或禁用来源 |
| `source autorank` / `source ranking` | 查看或调整安装来源优先级 |
| `search 关键词` | 搜索软件源和缓存 |
| `install 包名` | 根据来源优先级尝试安装 |
| `list [关键词]` / `remove 包名` | 查看或卸载已安装软件 |
| `update` / `upgrade` | 刷新索引 / 使用原生包管理器升级 |

支持 pacman、AUR、APT、DNF、APK、Flatpak、玲珑、Guix、Nix 和 Snap；实际可用来源取决于本机环境。按需查询的来源可能直接联网或调用本机工具；其他来源通常需要先运行 `dick update` 建立索引。可用 `--source pacman` 限定来源、`--json` 输出机器可读结果。完整选项见 `dick --help`。

配置示例见 [config.example.toml](config.example.toml)，默认配置路径为 `~/.config/dick/config.toml`，默认缓存路径为 `~/.cache/dick`。本版沿用上游的配置和缓存位置；已有配置中的 `[web]` 和 `[ai]` 段会被忽略。可以用 `--config` 和 `--cache-dir` 指定其他路径。

本版移除了上游指向原仓库的安装脚本及 `updateme` / `removeme` 命令。请用所选安装工具更新或卸载，以免意外恢复成上游完整版本。

## 测试

```sh
python -m unittest discover -s tests
```
