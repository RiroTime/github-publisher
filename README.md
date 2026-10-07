# publisher

你有几个仓库要往 GitHub 推。每个仓库一把部署钥匙（deploy key），而 GitHub 上一把钥匙只能开一个仓库的门。于是每次发布你要做一串动作：切目录、确认这是哪个仓库、确认用哪把钥匙、add、commit、push，push 完再回头核对「刚才推上去的到底是哪一份文件」。

这个仓库做的是：**把上面那一串收成一条命令，并且从设计上让它做不到「悄悄推」。**

```
staging_root ──manifest──▶ 清单 JSON ──push──▶ GitHub
                            （人点确认框）    （ssh-agent 签名）
```

---

## 它解决的具体麻烦

| 你会遇到的 | 它怎么处理 |
|---|---|
| 一把钥匙绑不了两个仓库 | 每个目标（target）配自己的钥匙，push 时自动切 |
| 推错仓库 / 推错分支 | 目标只写在 `config.json` 里，命令行只能报名字，不能报路径；分支必须在白名单内 |
| 手滑推上去不该推的东西 | 先出清单（manifest），清单里逐个列出文件名和大小，确认后才推 |
| 私钥被顺手拷走 | 私钥交给系统 ssh-agent，脚本只请求签名，从不读取、不解密、不复制、不打印 |
| 每次都要输一长串命令 | 五个动词：`doctor` / `init` / `manifest` / `push` / `status` |
| 换台电脑就不能用 | 文件里没有任何本机绝对路径，差异全在 `config.json` 的 `staging_root` |

---

## 它不是

- 不是 CI。没有后台、没有守护进程、没有定时任务。
- 不是密钥管理器。它不给钥匙加密，也不帮你保管。
- 不是给别的程序调的。没有 `--yes`、没有 `--force`、没有 `--cmd` —— **审批必须由坐在屏幕前的人在系统原生对话框里点**。

---

## 用起来

### 0. 前提

- Windows 上装有 OpenSSH 客户端（设置 → 应用 → 可选功能 → OpenSSH 客户端）
- 有 Python 3
- 目标仓库已在 GitHub 建好（空仓库，不要勾 README / .gitignore / license）

### 1. 初始化

```bash
python publisher.py init
```

生成本地骨架和一份 `config.json`。如果是从别处拷来的目录，`init` 会跳过已存在的文件。

### 2. 配目标

打开 `config.json`，在 `targets` 里填：

```json
{
  "name": "my-tool",
  "staging_root": "<这台机器上存放 my-tool 源码的目录>",
  "repo_slug": "<你的账号>/my-tool",
  "branches": ["main"],
  "key": "github-deploy-my-tool"
}
```

- `staging_root` —— 要发布的源码目录。**换电脑只改这一个字段。**
- `repo_slug` —— 仓库地址由此推导，`remote` 不用也不允许手填。
- `branches` —— 允许推的分支白名单。不在里面的直接拒。
- `key` —— 可选。这把钥匙的名字，对应 `keys/<名字>`。不填就按 `github-deploy-<name>` 找。

> **一个仓库一把钥匙，不能共用。** 一把 deploy key 在 GitHub 侧只能挂在一个仓库上，第二处再挂会报 `Key is already in use`。

### 3. 生成钥匙

命令行带参数，或者直接双击：

```bash
setup-key.cmd github-deploy-my-tool <你的账号>/my-tool
```

它会生成 ed25519 密钥、装进 ssh-agent、打印公钥。**会问你要口令 —— 必须设。** 没口令的钥匙不算边界：谁能读到文件谁就能推，脚本会直接把它删掉。

拿到公钥后去浏览器：`https://github.com/<owner>/<repo>/settings/keys` → Add deploy key → 粘贴 → **勾上 `Allow write access`**（不勾是只读，push 会失败）。

### 4. 日常三步

```bash
# ① 体检：工具链、钥匙、目标目录、分支白名单
python publisher.py doctor

# ② 出清单：列出将推送的文件
python publisher.py manifest --target my-tool

# ③ 推送：会弹一个系统对话框，点「是」才走
python publisher.py push --manifest manifests/my-tool-xxxxxxxxxxxx.json
```

`status` 看最近一次的推送回执。

---

## 建议的仓库布局

工具把它自己所在的目录当作工作根，所有状态都留在自己家里，不写 `~/.ssh/`：

```
publisher/
├── publisher.py            # 全部代码，一个文件
├── config.json             # 目标清单（含本机路径，别提交）
├── setup-key.cmd           # 生成部署钥匙
├── keys/                   # 私钥（绝不提交）
├── manifests/              # 每次出清单的 JSON
├── audit.log               # 谁在什么时候要推什么
├── receipts.log            # 推成功后的回执
└── known_hosts             # 主机指纹，不污染全局
```

本仓库自带的 `.gitignore` 已把 `keys/`、`config.json`、`manifests/`、两个 log、`known_hosts` 全部挡住。

---

## 安全边界（说清楚，不粉饰）

**能防住的：**

1. **密钥拿不到。** 私钥在 ssh-agent 里，脚本只发签名请求。所有 ssh 子进程一律 `BatchMode=yes` —— 拿不到 agent 就用不了密钥。这不是「我答应不用」，是「用不了」。
2. **范围锁死。** 目标写在 `config.json`，调用方只能报名字。想多发一个仓库，必须去改那个文件 —— 改动是可见、可审计的。
3. **审批不可绕过。** 弹的是系统原生对话框（`MessageBoxW`），默认按钮是「否」。命令行参数代替不了它。

**防不住的：**

- 对话框只有「是/否」，没有手输确认码（宿主 Python 无 tkinter）。它能防误触、能留痕，防不住针对性的 UI 自动化。
- deploy key 不会自动过期。唯一的断路动作是去 GitHub 把它删掉。

真正的硬边界是第 1 条和第 3 条 —— 密钥不可提取，加上单仓库范围。

---

## 许可

MIT
