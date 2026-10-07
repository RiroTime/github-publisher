#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
publisher —— 一个只做一件事的发布器（capability boundary）

===============================================================================
改这个文件之前，请先读完这几条约束。它们不是注释，是设计。
===============================================================================

1) 凭据不在这里。
   私钥交给系统 ssh-agent 托管。本脚本只请求 agent 签名，永远不读取、不解密、
   不复制、不打印私钥文件。所有需要 ssh 的子进程一律 BatchMode=yes ——
   拿不到 agent 就用不了密钥。这不是"我答应不用"，是"用不了"。

2) 审批点在本脚本自己弹的系统原生对话框里，命令行参数无法代替。
   没有 --yes，没有 --force，没有 --cmd，没有 --approve。
   谁能调用它不重要；谁坐在屏幕前点那个框才重要。

3) 目标写在 config.json 的 targets 里，不由命令行决定。
   调用方只报"名字"，不能报路径。想多发一个仓库，必须改那个文件——
   改动是可见、可审计的。
   3b) 每个 target 用各自那把部署钥匙。一把 deploy key 在 GitHub 侧只能绑一个
   仓库，所以多仓库必须各用各的；名字取 target 里配的 key，或 github-deploy-<target 名>，
   都没有则回落历史单键（老 target 行为不变）。见 key_for() / use_key()。

4) 只有五个动词：doctor / init / manifest / push / status。
   除此之外一律拒绝执行。

5) 【可复制性】这个文件里**没有任何本机绝对路径**。
   git / ssh 全部自动探测（见 discover()），本机差异只存在于 config.json。
   换电脑：拷目录 → 改 config.json 里的 staging_root → 跑 init + setup-key.cmd。

已知边界（不粉饰）：
  - 对话框只有「是/否」，没有"手输确认码"（宿主 Python 无 tkinter）。
    它能防误触、能留痕；防不住有针对性的 UI 自动化。
    真正的硬边界是第 1 条和第 3 条（密钥不可提取 + 单仓库范围）。
  - deploy key 不会自动过期。唯一的断路动作是去 GitHub 删掉它。
"""

import ctypes
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# =============================================================== 自身位置
HERE = os.path.dirname(os.path.abspath(__file__))
WB_HOME = os.path.dirname(HERE)                 # 通常 ~/.workbuddy
CONFIG_PATH = os.path.join(HERE, "config.json")
MANIFEST_DIR = os.path.join(HERE, "manifests")
RECEIPT_LOG = os.path.join(HERE, "receipts.log")
AUDIT_LOG = os.path.join(HERE, "audit.log")

KEY_DIR = os.path.join(HERE, "keys")
KEY_PATH = os.path.join(KEY_DIR, "github-deploy-default")
KEY_PUB = KEY_PATH + ".pub"
KEY_COMMENT = "publisher deploy key"


def key_for(target):
    """该 target 该用哪把钥匙 → (私钥, 公钥, 是否专属)。

    一把 deploy key 在 GitHub 侧只能绑一个仓库，所以多仓库必须各用各的钥匙。
    钥匙名 = target 里配的 key，或 github-deploy-<target 名>。
    两者都没有（老 target 没配 key）→ 回落到历史单键，行为与从前完全一致。

    显式配了 key 的 target 不回落到别的钥匙：缺就是缺，宁可报错也不换一把推。
    """
    target = target or {}
    explicit = target.get("key")
    name = explicit or ("github-deploy-%s" % target.get("name", ""))
    if name:
        priv = os.path.join(KEY_DIR, name)
        if os.path.exists(priv + ".pub"):
            return priv, priv + ".pub", True
    if explicit:
        return os.path.join(KEY_DIR, explicit), os.path.join(KEY_DIR, explicit) + ".pub", True
    priv = os.path.join(KEY_DIR, "github-deploy-default")
    return priv, priv + ".pub", False


def use_key(target):
    """按 target 切换 KEY_PATH / KEY_PUB。找不到专属钥匙就不动。

    KEY_PATH / KEY_PUB 是被 child_env 与 toolchain_bad 在**运行时**读取的，
    所以在 cmd_push 开头调一次即可全局生效，不必改各函数的签名。
    """
    global KEY_PATH, KEY_PUB
    priv, pub, own = key_for(target)
    if own:
        KEY_PATH, KEY_PUB = priv, pub

KNOWN_HOSTS = os.path.join(HERE, "known_hosts")   # 主机密钥也放自己家，不写 ~/.ssh/
KNOWN_HOST_ALIASES = ("github.com",)

VERBS = ("doctor", "init", "manifest", "push", "status")

CONFIG_TEMPLATE = {
    "_help": ("tools 里留空 = 自动探测；targets 每项只需 name / staging_root / "
              "repo_slug / branches。换电脑只改 staging_root。"
              "remote 地址由 repo_slug 推导，不用也不允许手填。"),
    "tools": {"git": "", "ssh": "", "ssh-add": "", "ssh-keygen": "", "ssh-keyscan": ""},
    "targets": [],
}


# =============================================================== 工具链探测
def _first(*cands):
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def _portablegit_candidates(rel):
    """扫 WorkBuddy 托管的 PortableGit，版本目录名不写死。"""
    out = []
    vdir = os.path.join(WB_HOME, "binaries", "PortableGit", "versions")
    if os.path.isdir(vdir):
        for v in sorted(os.listdir(vdir), reverse=True):
            out.append(os.path.join(vdir, v, rel))
    return out


def discover():
    """把 git / ssh 找出来。优先 Windows 自带的 OpenSSH —— 它才能连上
    系统 agent 的命名管道（MSYS 版 ssh 找 Unix socket，连不上会误报不可达）。"""
    sshd = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "OpenSSH")
    return {
        "git": _first(shutil.which("git"),
                      *_portablegit_candidates(os.path.join("cmd", "git.exe")),
                      r"C:\Program Files\Git\cmd\git.exe"),
        "ssh": _first(os.path.join(sshd, "ssh.exe"), shutil.which("ssh")),
        "ssh-add": _first(os.path.join(sshd, "ssh-add.exe"), shutil.which("ssh-add")),
        "ssh-keygen": _first(os.path.join(sshd, "ssh-keygen.exe"),
                             shutil.which("ssh-keygen")),
        "ssh-keyscan": _first(os.path.join(sshd, "ssh-keyscan.exe"),
                              shutil.which("ssh-keyscan")),
    }


_TOOLS = None


def T(name):
    """工具路径：config.json 里填了就用手填的，留空用探测结果。"""
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = discover()
        for k, v in (load_config(require=False).get("tools") or {}).items():
            if v:
                _TOOLS[k] = v
    return _TOOLS.get(name)


def load_config(require=True):
    if not os.path.exists(CONFIG_PATH):
        if require:
            raise SystemExit("拒绝：找不到 %s —— 先跑 publisher init 生成。" % CONFIG_PATH)
        return {}
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def target_by_name(name):
    targets = load_config().get("targets") or []
    for t in targets:
        if t.get("name") == name:
            slug = t["repo_slug"]
            return {
                "name": t["name"],
                "staging_root": t["staging_root"],
                "repo_slug": slug,
                "branches": t.get("branches") or ["main"],
                # key 必须原样带出来，key_for 靠它选钥匙。这里漏过一次：
                # 显式配的钥匙被静默忽略，一路回落成 default。回落名恰好
                # 等于显式名的（github-publisher）蒙对了，对不上的
                # （dvlaa，回落名会带版本号）就被推成 default，遭 GitHub
                # 拒绝为 "denied to deploy key"，而 doctor 读的是 config
                # 原文、不走这里，所以看不出异常。
                "key": t.get("key"),
                "ssh_remote": "git@github.com:%s.git" % slug,
                "anon_url": "https://github.com/%s.git" % slug,
            }
    raise SystemExit("拒绝：目标 %r 不在白名单里。可用的：%s"
                     % (name, ", ".join(t.get("name", "?") for t in targets) or "（空）"))


# =============================================================== 基础工具
def child_env(over_ssh):
    e = dict(os.environ)
    e["GIT_TERMINAL_PROMPT"] = "0"      # 绝不弹交互式凭据框
    e["GIT_ASKPASS"] = "cmd /c exit"    # 任何询问一律空答
    e["SSH_ASKPASS"] = "cmd /c exit"
    e["SSH_ASKPASS_REQUIRE"] = "never"  # 绝不允许弹口令输入
    e.pop("SSH_AUTH_SOCK", None)        # 让 Windows ssh 走默认命名管道找 agent
    if over_ssh:
        # -i 指向 .pub：只从 agent 里挑这把身份，压根不读私钥文件本体
        # BatchMode=yes：agent 里没有就不许问口令，直接失败
        e["GIT_SSH_COMMAND"] = (
            '"{ssh}" -o BatchMode=yes -o IdentitiesOnly=yes'
            ' -o StrictHostKeyChecking=accept-new'
            ' -o "UserKnownHostsFile={kh}"'
            ' -i "{pub}"'
        ).format(ssh=T("ssh"), pub=KEY_PUB, kh=KNOWN_HOSTS)
    return e


def run(cmd, cwd=None, over_ssh=False):
    return subprocess.run(
        cmd, cwd=cwd, env=child_env(over_ssh),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def parent_image_name(pid):
    """父进程的可执行名——用来回答"这次是谁调的"。"""
    try:
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(1024)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
        finally:
            k32.CloseHandle(h)
    except Exception:
        pass
    return None


def audit(verb, detail):
    os.makedirs(HERE, exist_ok=True)
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "verb": verb,
            "argv": sys.argv[1:],
            "caller": parent_image_name(os.getppid()),
            "caller_pid": os.getppid(),
            "detail": detail,
        }, ensure_ascii=False) + "\n")


def confirm_dialog(title, text):
    """系统原生模态框。默认按钮是「否」。返回 True 仅当人手点了「是」。"""
    MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2, MB_TOPMOST, MB_SETFOREGROUND = (
        0x4, 0x30, 0x100, 0x40000, 0x10000)
    flags = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SETFOREGROUND
    return ctypes.windll.user32.MessageBoxW(0, text, title, flags) == 6  # IDYES


# =============================================================== 读仓库状态
def read_head(target):
    root = target["staging_root"]
    if not os.path.isdir(os.path.join(root, ".git")):
        raise SystemExit("拒绝：%s 不是 git 仓库" % root)

    def g(*args):
        p = run([T("git")] + list(args), cwd=root)
        if p.returncode != 0:
            raise SystemExit("git %s 失败：%s" % (" ".join(args), p.stderr.strip()))
        return p.stdout

    commit = g("rev-parse", "HEAD").strip()
    tree = g("rev-parse", "HEAD^{tree}").strip()
    subject = g("log", "-1", "--format=%s").strip()
    authored = g("log", "-1", "--format=%an <%ae>").strip()

    files = []
    for line in g("ls-tree", "-r", "-l", "HEAD").splitlines():
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) >= 4 and parts[1] == "blob":
            files.append({"path": path, "blob": parts[2], "bytes": int(parts[3])})
    files.sort(key=lambda f: f["path"])

    dirty = [l for l in g("status", "--porcelain").splitlines() if l.strip()]
    return commit, tree, subject, authored, files, dirty


def manifest_body(m):
    """去掉 manifest_sha 后的规范化正文，用于算指纹。"""
    b = {k: v for k, v in m.items() if k != "manifest_sha"}
    return json.dumps(b, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def manifest_sha(m):
    return hashlib.sha256(manifest_body(m).encode("utf-8")).hexdigest()


def seed_known_hosts():
    """把 GitHub 的主机密钥预置到本目录，绝不写 ~/.ssh/known_hosts。"""
    if os.path.exists(KNOWN_HOSTS) and os.path.getsize(KNOWN_HOSTS) > 0:
        print("  已存在，跳过抓取：%s" % KNOWN_HOSTS)
    else:
        p = run([T("ssh-keyscan")] + list(KNOWN_HOST_ALIASES))
        if p.returncode != 0 or not p.stdout.strip():
            print("  抓取失败：%s" % (p.stderr.strip() or "无输出（网络不通？）"))
            return
        with open(KNOWN_HOSTS, "w", encoding="utf-8") as f:
            f.write(p.stdout)
        print("  已写入 %s（%d 条）" % (KNOWN_HOSTS, len(p.stdout.strip().splitlines())))
    p = run([T("ssh-keygen"), "-lf", KNOWN_HOSTS])
    for line in p.stdout.splitlines():
        print("    " + line)
    print("  请把上面的指纹与 GitHub 官方公布的 SSH 主机密钥指纹核对一遍：")
    print("  https://docs.github.com/en/authentication/keeping-your-account-and-data-"
          "secure/githubs-ssh-key-fingerprints")


def toolchain_bad():
    """推得动吗？在弹框之前先问清楚——别让人点了「是」才发现推不上去。"""
    for key, label in (("git", "git"), ("ssh", "ssh"), ("ssh-add", "ssh-add"),
                       ("ssh-keygen", "ssh-keygen")):
        if not T(key):
            return ("找不到 %s。装一个 git（Git for Windows 自带 OpenSSH），"
                    "或在 config.json 的 tools 里手填路径。" % label)
    if not os.path.exists(KNOWN_HOSTS):
        return "主机密钥文件不存在，先跑 publisher init（%s）" % KNOWN_HOSTS
    if not os.path.exists(KEY_PUB):
        return "公钥不存在，先跑 publisher init + 双击 setup-key.cmd（%s）" % KEY_PUB

    parts = run([T("ssh-keygen"), "-lf", KEY_PUB]).stdout.split()
    fp = parts[1] if len(parts) > 1 else None
    p = run([T("ssh-add"), "-l"])
    if p.returncode != 0:
        return ("ssh-agent 不可达：%s（Windows「服务」里确认 "
                "OpenSSH Authentication Agent 正在运行）" % (p.stderr.strip() or "未启动"))
    if not fp or not any(fp in line for line in p.stdout.strip().splitlines()):
        return "部署密钥不在 agent 里，先双击 setup-key.cmd 载入：%s" % KEY_PATH
    return None


# =============================================================== 五个动词
def cmd_doctor(_):
    print("== 配置 ==")
    print("  配置文件  %s  %s" % (CONFIG_PATH,
                                 "存在" if os.path.exists(CONFIG_PATH) else "不存在（跑 init）"))
    print("  自检位置  %s" % HERE)

    print("\n== 工具链（自动探测，可用 config.json 覆盖）==")
    for k in ("git", "ssh", "ssh-add", "ssh-keygen", "ssh-keyscan"):
        print("  %-12s %s" % (k, T(k) or "!! 没找到"))

    print("\n== 密钥 ==")
    fp = None
    if os.path.exists(KEY_PUB):
        parts = run([T("ssh-keygen"), "-lf", KEY_PUB]).stdout.split()
        fp = parts[1] if len(parts) > 1 else None
        print("  公钥：存在  指纹 %s" % (fp or "读不出"))
    else:
        print("  公钥：不存在 —— 跑 publisher init")
    if not os.path.exists(KEY_PATH):
        print("  私钥：不存在 —— 跑 publisher init")
    else:
        print("  私钥：存在 %s" % KEY_PATH)
        # 空口令能解出来 = 没有口令 = 任何进程读走这个文件就能直接推送 = 边界作废
        p = run([T("ssh-keygen"), "-y", "-P", "", "-f", KEY_PATH])
        if p.returncode == 0 and p.stdout.strip().startswith("ssh-"):
            print("  !! 警告：这把私钥没有口令。任何进程读走这个文件就能直接推送。")
            print("     请删掉重新生成，生成时务必设口令。")
        else:
            print("  口令：已设置（空口令解不开，符合预期）")

    print("\n== 主机密钥 ==")
    print("  %s  %s" % (KNOWN_HOSTS,
                       "存在" if os.path.exists(KNOWN_HOSTS) else "不存在（跑 init 抓取）"))

    print("\n== ssh-agent ==")
    p = run([T("ssh-add"), "-l"]) if T("ssh-add") else None
    loaded = p.stdout.strip().splitlines() if p and p.returncode == 0 else []
    if p and p.returncode == 0:
        print("  agent 可达，已载入 %d 个身份：" % len(loaded))
        for line in loaded:
            print("    " + line)
    elif p and p.returncode == 1:
        print("  agent 可达，但里面没有身份 —— 双击 setup-key.cmd")
    else:
        print("  agent 不可达：%s" % ((p.stderr.strip() if p else "ssh-add 缺失") or "未启动"))
    if fp:
        print("  部署密钥：%s" % ("已载入 agent，可以推送"
                                 if any(fp in l for l in loaded)
                                 else "不在 agent 里 —— 推送会失败"))

    print("\n== 能力白名单（config.json 的 targets）==")
    targets = load_config(require=False).get("targets") or []
    if not targets:
        print("  （空）—— 照 config.json 里 _help 说的格式加一条")
    for t in targets:
        ok = os.path.isdir(t.get("staging_root", ""))
        print("  %-28s %s" % (t.get("name"), "目录存在" if ok else "!! 目录不存在"))
        print("      -> %s  分支 %s" % (t.get("repo_slug"),
                                       ",".join(t.get("branches") or ["main"])))
        _priv, _pub, _own = key_for(t)
        print("         钥匙 %s%s  %s"
              % (os.path.basename(_priv), "" if _own else "（回落历史单键）",
                 "已生成" if os.path.exists(_pub) else "!! 还没生成"))
    return 0


def cmd_init(_):
    os.makedirs(KEY_DIR, exist_ok=True)
    print("一次性配置。五步，人的动作脚本代替不了。\n")

    print("第 0 步 · 生成本机配置（脚本自动做）")
    if os.path.exists(CONFIG_PATH):
        print("  已存在，跳过：%s" % CONFIG_PATH)
    else:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(CONFIG_TEMPLATE, f, ensure_ascii=False, indent=2)
        print("  已写入 %s（targets 为空，需要照 _help 加一条）" % CONFIG_PATH)
    seed_known_hosts()
    print()

    print("第 1 步 · 生成部署密钥（务必设口令，口令别告诉任何人）")
    print('  "%s" -t ed25519 -C "%s" -f "%s"' % (T("ssh-keygen"), KEY_COMMENT, KEY_PATH))
    print("  或者直接双击 setup-key.cmd，它把第 1、2 步连起来做。")
    print("  注：这一步会问 passphrase，必须填。私钥在磁盘上是加密的，")
    print("      这样即使文件被读走也用不了——这是整个边界的根。\n")

    print("第 2 步 · 把密钥交给 agent（每次重启电脑后一次，会让你再输一遍口令）")
    print('  "%s" "%s"' % (T("ssh-add"), KEY_PATH))
    print("  验证：ssh-add -l 应该能看到这把 key。\n")

    print("第 3 步 · 在 GitHub 上授权（只能你点）")
    for t in (load_config(require=False).get("targets") or []):
        print("  打开 https://github.com/%s/settings/keys" % t.get("repo_slug"))
        print("  → Add deploy key")
        print("  → Title 随便填；Key 粘贴下面的公钥内容")
        print("  → **勾上 Allow write access**（不勾就是只读，推不上去）")
        print("  → Add key\n")
        break
    if os.path.exists(KEY_PUB):
        print("  公钥内容（复制这一整行）：")
        print("  " + open(KEY_PUB, encoding="utf-8").read().strip())
    else:
        print("  公钥还没有——先做完第 1 步再来这里取。")

    print("\n第 4 步 · 换电脑时怎么做（这套东西就是为这个设计的）")
    print("  1) 把整个 publisher 目录拷到新机器（keys/ 建议**不要**拷）")
    print("  2) 改 config.json 里的 staging_root，指向新机器上的仓库路径；其余不用动")
    print("  3) 在新机器双击 setup-key.cmd 生成**新**密钥，去同一个仓库再加一把")
    print("     deploy key（一个仓库可以挂多把）。旧机器不用了就把那把删掉。")
    print("  路径不用手填——git 和 ssh 都是自动探测的。")
    print("\n做完跑 publisher doctor 复查。")
    return 0


def cmd_manifest(args):
    target = target_by_name(args["target"])
    commit, tree, subject, authored, files, dirty = read_head(target)

    m = {
        "target": target["name"],
        "repo_slug": target["repo_slug"],
        "ssh_remote": target["ssh_remote"],
        "anon_url": target["anon_url"],
        "branch": target["branches"][0],
        "commit": commit,
        "tree": tree,
        "commit_subject": subject,
        "commit_author": authored,
        "files": files,
        "dirty": dirty,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    m["manifest_sha"] = manifest_sha(m)

    os.makedirs(MANIFEST_DIR, exist_ok=True)
    path = os.path.join(MANIFEST_DIR, "%s-%s.json" % (target["name"], commit[:12]))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)

    total = sum(f["bytes"] for f in m["files"])
    print("清单已生成：%s" % path)
    print("  目标     %s  分支 %s" % (m["repo_slug"], m["branch"]))
    print("  提交     %s  %s" % (commit[:12], subject))
    print("  文件     %d 个，共 %.1f KB" % (len(m["files"]), total / 1024))
    print("  指纹     %s" % m["manifest_sha"][:16])
    if dirty:
        print("  注意：工作区有 %d 处未提交改动。发布的是 commit %s，不是工作区。"
              % (len(dirty), commit[:12]))
    print("\n下一步：publisher push --manifest \"%s\"" % path)
    audit("manifest", {"target": target["name"], "commit": commit, "files": len(files)})
    return 0


# 只有这些字样才允许重试。权限类错误绝不在内——
# "Permission denied" / "does not have write access" 必须立刻返回，不能掩盖。
TRANSIENT_MARKERS = (
    "kex_exchange_identification", "Connection closed", "Connection reset",
    "Operation timed out", "Connection timed out", "Could not resolve hostname",
)


def push_with_retry(remote, refspec, cwd, tries=3):
    """网络抖自动重试。批准过的内容 + 同一个 commit，重试不改变意图。"""
    last = None
    for i in range(1, tries + 1):
        p = run([T("git"), "push", remote, refspec], cwd=cwd, over_ssh=True)
        last = p
        if p.returncode == 0:
            return p, i
        blob = (p.stdout or "") + (p.stderr or "")
        if not any(t in blob for t in TRANSIENT_MARKERS):
            return p, i          # 不是抖动，别重试，如实报错
        if i < tries:
            print("  第 %d 次遇到网络抖动，4 秒后重试…" % i)
            time.sleep(4)
    return last, tries


def cmd_push(args):
    mpath = os.path.abspath(args["manifest"])
    if not mpath.startswith(os.path.abspath(MANIFEST_DIR) + os.sep):
        raise SystemExit("拒绝：清单必须位于 %s 之内" % MANIFEST_DIR)
    m = json.load(open(mpath, encoding="utf-8"))

    if m.get("manifest_sha") != manifest_sha(m):
        raise SystemExit("拒绝：清单指纹不符，文件被改过。")
    target = target_by_name(m["target"])
    use_key(target)          # 先切到该 target 的钥匙，toolchain_bad 靠它做前置检查
    if m["branch"] not in target["branches"]:
        raise SystemExit("拒绝：分支 %s 不在白名单 %s 内" % (m["branch"], target["branches"]))
    if m["ssh_remote"] != target["ssh_remote"] or m["repo_slug"] != target["repo_slug"]:
        raise SystemExit("拒绝：清单里的目标地址与白名单不一致。")

    bad = toolchain_bad()
    if bad:
        raise SystemExit("拒绝：环境没准备好 —— %s" % bad)

    # ---- 审批前重算：确认"清单描述的" == "现在仓库里的"
    commit, tree, _subject, _authored, files, dirty = read_head(target)
    if (commit != m["commit"] or tree != m["tree"] or files != m["files"]):
        raise SystemExit(
            "拒绝：仓库内容在生成清单之后变了。\n"
            "  清单 commit %s / 现在 %s\n"
            "  请重新生成清单，走一遍审批。" % (m["commit"][:12], commit[:12]))

    code = "%06d" % random.randint(0, 999999)
    total = sum(f["bytes"] for f in m["files"])
    listed = m["files"][:15]
    more = "" if len(m["files"]) <= 15 else "\n   …（另有 %d 个）" % (len(m["files"]) - 15)

    text = (
        "要向下面这个仓库推送内容：\n\n"
        "仓库   {repo}\n"
        "分支   {branch}\n"
        "提交   {sha}  {subj}\n"
        "作者   {auth}\n"
        "文件   {n} 个，共 {kb:.1f} KB\n\n"
        "文件清单：\n{lst}{more}\n\n"
        "{dirty}"
        "回执码 {code}（会记进 receipts.log）\n\n"
        "点「是」= 批准并推送；点「否」= 取消。\n"
        "权限范围仅限这一个仓库。"
    ).format(
        repo=m["repo_slug"], branch=m["branch"], sha=m["commit"][:12],
        subj=m["commit_subject"], auth=m["commit_author"],
        n=len(m["files"]), kb=total / 1024,
        lst="\n".join("   " + f["path"] for f in listed), more=more,
        dirty=("注意：工作区有 %d 处未提交改动（不会被推送）。\n\n" % len(dirty)) if dirty else "",
        code=code,
    )

    if not confirm_dialog("publisher · 发布确认", text):
        _receipt(m, code, "DENIED", None, None, None)
        print("已取消（回执码 %s）。" % code)
        return 1

    p, tries = push_with_retry(m["ssh_remote"],
                               "%s:refs/heads/%s" % (m["commit"], m["branch"]),
                               target["staging_root"])
    if p.returncode != 0:
        _receipt(m, code, "PUSH_FAILED", p.stderr.strip(), None, None)
        print("推送失败（试了 %d 次）：\n%s\n%s"
              % (tries, p.stdout.strip(), p.stderr.strip()))
        return 1

    # ---- 验收：远程分支 SHA == 我们那个 commit 的 SHA
    # commit SHA 是整棵树的密码学哈希，相同即逐字节相同，无需逐文件比对。
    v = run([T("git"), "-c", "credential.helper=", "ls-remote",
             m["anon_url"], "refs/heads/%s" % m["branch"]])
    remote = v.stdout.split()[0] if v.stdout.strip() else None
    matched = (remote == m["commit"])

    _receipt(m, code, "PUSHED", p.stderr.strip(), remote, matched)
    print("已推送。回执码 %s" % code)
    print("  本地 commit  %s" % m["commit"])
    print("  远程 commit  %s" % (remote or "（读不到）"))
    print("  验收         %s" % ("通过：内容逐字节一致" if matched
                                 else "未通过：远程 SHA 与本地不一致，请查 receipts.log"))
    print("  仓库         https://github.com/%s/tree/%s" % (m["repo_slug"], m["branch"]))
    print("\n收尾提醒：用完请去仓库 Settings → Deploy keys 删掉这把 key，")
    print("          那是唯一能让本脚本立刻失去推送能力的动作。")
    return 0 if matched else 1


def _receipt(m, code, verdict, err, remote, matched):
    os.makedirs(HERE, exist_ok=True)
    with open(RECEIPT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "code": code,
            "verdict": verdict,
            "repo": m["repo_slug"],
            "branch": m["branch"],
            "commit": m["commit"],
            "files": len(m["files"]),
            "bytes": sum(x["bytes"] for x in m["files"]),
            "manifest_sha": m["manifest_sha"],
            "remote_sha": remote,
            "matched": matched,
            "caller": parent_image_name(os.getppid()),
            "error": (err or "")[:800],
        }, ensure_ascii=False) + "\n")
    audit("push", {"code": code, "verdict": verdict, "commit": m["commit"]})


def cmd_status(_):
    print("配置：%s" % CONFIG_PATH)
    print("自检位置：%s" % HERE)
    print("\n能力白名单：")
    for t in (load_config(require=False).get("targets") or []):
        print("  %-28s %s  分支 %s" % (t.get("name"), t.get("repo_slug"),
                                       ",".join(t.get("branches") or ["main"])))
    loaded = 0
    if T("ssh-add"):
        p = run([T("ssh-add"), "-l"])
        loaded = len(p.stdout.strip().splitlines()) if p.returncode == 0 else 0
    print("\nagent：%s" % ("已载入 %d 个身份" % loaded if loaded else "没有可用身份"))
    if os.path.exists(RECEIPT_LOG):
        lines = open(RECEIPT_LOG, encoding="utf-8").read().strip().splitlines()
        print("\n最近回执（共 %d 条）：" % len(lines))
        for line in lines[-5:]:
            r = json.loads(line)
            print("  %s  %s  %s  %s  %s" % (r["ts"], r["code"], r["verdict"],
                                            r["commit"][:10],
                                            "内容一致" if r.get("matched") else
                                            ("已取消" if r["verdict"] == "DENIED" else "-")))
    else:
        print("\n还没有回执。")
    return 0


# =============================================================== 入口
def parse(argv):
    if not argv or argv[0] not in VERBS:
        raise SystemExit("用法：publisher {%s}" % "|".join(VERBS))
    verb, rest = argv[0], argv[1:]
    # 显式白名单解析：未知开关一律拒绝，绝不忽略
    opts = {}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--target", "--manifest") and i + 1 < len(rest):
            opts[a[2:]] = rest[i + 1]
            i += 2
        else:
            raise SystemExit("拒绝：不认识的参数 %r。本脚本只接受 --target / --manifest。" % a)
    for k in {"manifest": ["target"], "push": ["manifest"]}.get(verb, []):
        if k not in opts:
            raise SystemExit("用法：publisher %s --%s <值>" % (verb, k))
    return verb, opts


if __name__ == "__main__":
    verb, opts = parse(sys.argv[1:])
    sys.exit({"doctor": cmd_doctor, "init": cmd_init, "manifest": cmd_manifest,
              "push": cmd_push, "status": cmd_status}[verb](opts))
