#!/usr/bin/env python3
"""默认只检查；--push 在隔离副本中生成一个提交，再确认普通推送到 main。"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

REMOTE_URLS = {
    "https://github.com/spumon1/SUCK_MY_ASTRA.git",
    "git@github.com:spumon1/SUCK_MY_ASTRA.git",
}
ROOT_FILES = {"README.md", "LICENSE", "FINDINGS.md", "HANDOFF.md",
              ".gitignore", "config.example.yaml"}
EXACT_FILES = {"go/go.mod", "go/go.sum", "go/unified_bank.json",
               "relay/s.yaml", "relay/.fcignore"}
SUFFIXES = {"go": {".go", ".html"}, "relay": {".js", ".md"},
            "scripts": {".py", ".sh"}, "design": {".md", ".html"},
            "tests/ui": {".cjs", ".md"}, ".github/workflows": {".yml", ".yaml"}}
PRIVATE_KEY = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----")
# 仅认可已核对的本机 TLS 道具，不给整个测试文件发免检金牌。
FIXTURE_PATH = "relay/index.test.js"
FIXTURE_SHA256 = "fdcb8c36d482b0dcee6e0b0e6800277c256fa95c78025c0798402765fa2bd4aa"
RFC_NONCE_LINE_SHA256 = "7d6c0d9422326a76d03439d065120a285eabb3f29ff0257ae4e3b73114bfebf0"
PERSONAL_EMAIL = re.compile(r"@[\w.-]*\b(?:gmail|outlook|hotmail|qq|163)\.com", re.I)
MAX_TEXT_BYTES = 10 * 1024 * 1024
AUTH_ENV = {"GIT_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT"}


def git_failure(argv, result):
    """只输出预设诊断，不把 Git 错误里的 URL、口令和个人信息搬上台。"""
    parts = iter(argv[1:])
    action = "operation"
    for part in parts:
        if part in {"-C", "-c"}:
            next(parts, None)
        elif not part.startswith("-"):
            action = part
            break
    detail = result.stderr.decode(errors="replace").lower()
    cases = (
        (("could not read username", "could not read password", "authentication failed", "invalid username or token"),
         "HTTPS 认证凭据不可用。请自行运行 gh auth login --hostname github.com --git-protocol https --web，再重试"),
        (("permission denied (publickey)",), "SSH 认证失败，请检查 SSH 密钥与 ssh-agent"),
        (("remote branch main not found",), "远端 main 不存在；脚本不会自动创建或覆盖分支"),
        (("repository not found",), "仓库不存在或当前账号无权访问，请核对账号和仓库权限"),
        (("protected branch", "gh013", "workflow", "403", "write access", "permission to"),
         "写权限、工作流权限或分支规则拒绝操作；请核对授权，不要强推或绕过保护"),
        (("non-fast-forward", "fetch first"), "远端已前进，请重新审核运行；不要强推"),
        (("could not resolve", "failed to connect", "timed out", "ssl certificate"),
         "网络、代理或证书连接失败；请检查网络，不要关闭证书校验"),
        (("failed to sign", "gpg failed"), "提交签名失败，请检查本机签名配置；未自动跳过签名"),
    )
    hint = next((message for patterns, message in cases if any(p in detail for p in patterns)),
                "具体输出已隐藏以免泄密；请根据操作阶段继续排查")
    return f"git {action} 执行失败（退出 {result.returncode}）：{hint}；未继续推送"


def command(argv, cwd):
    """不经 shell 拼接；错误不回显可能夹带凭据的工具输出。"""
    env = {k: v for k, v in os.environ.items()
           if k in AUTH_ENV or not k.startswith(("GIT_", "GITLEAKS_"))}
    # 保留认证助手，但隔离 GIT_DIR/INDEX 等仓库指向；缺凭据时不藏着等输入。
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=300)
    if result.returncode:
        if Path(argv[0]).name == "git":
            raise RuntimeError(git_failure(argv, result))
        raise RuntimeError(f"{Path(argv[0]).name} 执行失败（退出 {result.returncode}）；未继续推送")
    return result.stdout


def git(root, *args):
    return command(["git", "-C", str(root), *args], root)


def allowed(name):
    path = Path(name)
    return (name in ROOT_FILES or name in EXACT_FILES
            or path.suffix in SUFFIXES.get(path.parent.as_posix(), set()))


def safe_path(root, name):
    """逐层拒绝符号链接，别让送文件的伙计被假门牌带出仓库。"""
    rel = Path(name)
    if rel.is_absolute() or ".." in rel.parts or ".git" in rel.parts:
        raise RuntimeError("拒绝越界路径")
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError(f"拒绝符号链接：{name}")
    return current


def export_worktree(root, target):
    """按发布白名单取当前文件，不带本地历史，也不使用原仓库暂存区。"""
    names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    selected = []
    for name in sorted(set(filter(None, names.decode().split("\0")))):
        if not allowed(name):
            continue
        source = safe_path(root, name)
        if not source.is_file():
            raise RuntimeError(f"文件缺失，不自动同步删除：{name}")
        destination = safe_path(target, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        selected.append(name)
    if not selected:
        raise RuntimeError("没有可发布文件")
    return selected


def scan_text(name, raw):
    if len(raw) > MAX_TEXT_BYTES or b"\0" in raw:
        raise RuntimeError(f"拒绝未审查的大文件或二进制：{name}")
    text = raw.decode("utf-8")
    for number, line in enumerate(text.splitlines(), 1):
        if PERSONAL_EMAIL.search(line):
            raise RuntimeError(f"疑似个人邮箱，先改为示例地址：{name}:{number}")
    # 仅在扫描副本屏蔽字节完全一致的已知测试道具；上传内容不自动改写。
    def inspect(match):
        digest = hashlib.sha256(match[0].encode()).hexdigest()
        if name != FIXTURE_PATH or digest != FIXTURE_SHA256:
            raise RuntimeError(f"检测到未经认可的私钥：{name}")
        return "TEST_TLS_FIXTURE" + "\n" * match[0].count("\n")
    text = PRIVATE_KEY.sub(inspect, text)
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        digest = hashlib.sha256(line.rstrip("\n").encode()).hexdigest()
        if name == FIXTURE_PATH and digest == RFC_NONCE_LINE_SHA256:
            lines[index] = "// RFC6455 public sample nonce\n"
    return "".join(lines)


def scan_tree(source, work, scanner):
    """强制内置规则、禁用行内豁免，扫描器缺失/报错都不能开门。"""
    work.mkdir()
    scan = work / "content"
    scan.mkdir()
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(source).as_posix()
        safe_path(source, name)
        text = scan_text(name, path.read_bytes())
        dest = scan / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    policy, ignore, report = work / "policy.toml", work / "ignore", work / "report.json"
    policy.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    ignore.write_text("", encoding="utf-8")
    argv = [scanner, "dir", str(scan), "--config", str(policy),
            "--gitleaks-ignore-path", str(ignore), "--ignore-gitleaks-allow",
            "--redact=100", "--no-banner", "--report-format", "json",
            "--report-path", str(report), "--max-decode-depth", "2"]
    try:
        command(argv, work)
    except RuntimeError:
        if report.exists():
            for finding in json.loads(report.read_text()) or []:
                print(f"拦截：{finding.get('File')}:{finding.get('StartLine')} "
                      f"规则={finding.get('RuleID')}", file=sys.stderr)
        raise RuntimeError("敏感信息扫描未通过；只报告位置，不回显秘密") from None


def archived_text(repo, target):
    """复查真正提交的 blob，防提交钩子改了暂存区却没改工作文件。"""
    target.mkdir()
    archive = io.BytesIO(git(repo, "archive", "--format=tar", "HEAD"))
    with tarfile.open(fileobj=archive) as members:
        for item in members:
            dest = safe_path(target, item.name)
            if item.isdir():
                continue
            if not item.isfile():
                raise RuntimeError(f"远端树包含需人工审核的链接：{item.name}")
            raw = members.extractfile(item).read()
            # 历史已有图片不重传、不做 OCR；新文件受发布白名单约束。
            if Path(item.name).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".ico"}:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
    metadata = target / ".push-main-commit-metadata.txt"
    if metadata.exists():
        raise RuntimeError("提交元数据审核文件发生命名冲突")
    metadata.write_bytes(git(repo, "show", "--no-patch", "--format=%B%n%an <%ae>%n%cn <%ce>", "HEAD"))


def prepare_commit(repo, work, args):
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    selected = args.selected
    for name in selected:
        dest = safe_path(repo, name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / "export" / name, dest)
    git(repo, "add", "--", *selected)
    changed = git(repo, "diff", "--cached", "--name-only", "-z")
    if not changed:
        print("远端 main 已是这些内容，无需新提交。")
        return None
    print(git(repo, "diff", "--cached", "--stat").decode())
    git(repo, "-c", f"user.name={args.author_name}", "-c",
        f"user.email={args.author_email}", "commit", "-m", args.message)
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    parents = git(repo, "rev-list", "--parents", "-n", "1", "HEAD").decode().split()
    changes = git(repo, "diff", "--name-only", "-z", base, head).decode().split("\0")
    if parents != [head, base] or not set(filter(None, changes)) <= set(selected):
        raise RuntimeError("提交历史或文件范围发生额外变化，停止推送")
    final = work / "committed"
    archived_text(repo, final)
    scan_tree(final, work / "final-scan", args.gitleaks)
    return head


def push_snapshot(root, work, args):
    remote = git(root, "remote", "get-url", "origin").decode().strip()
    if remote not in REMOTE_URLS:
        raise RuntimeError("origin 不是预期 GitHub 仓库或 URL 携带凭据，拒绝推送")
    repo = work / "repository"
    command(["git", "clone", "--single-branch", "--branch", "main",
             "--no-tags", "--", remote, str(repo)], work)
    head = prepare_commit(repo, work, args)
    if head is None:
        return
    git(repo, "-c", "push.followTags=false", "-c", "remote.origin.mirror=false",
        "push", "--dry-run", "--no-force", "--no-follow-tags", remote, f"{head}:refs/heads/main")
    print("目标：spumon1/SUCK_MY_ASTRA → main；普通推送，不 force。")
    print(f"待推提交：{head}；审核副本：{repo}")
    print("请先审核副本和变更内容；扫描不能保证识别所有敏感信息。")
    if input("确认推送请输入 PUSH main：").strip() != "PUSH main":
        print("未确认，未推送；副本保留供审核。")
        return
    # 使用已扫描的精确提交，不带分支后来变化；远端前进则由普通 push 拒绝。
    git(repo, "-c", "push.followTags=false", "-c", "remote.origin.mirror=false",
        "push", "--no-force", "--no-follow-tags", remote, f"{head}:refs/heads/main")
    print("已推送 main；原工作区、分支、暂存区和本地历史未改。")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="仅本地检查（默认）")
    mode.add_argument("--push", action="store_true", help="扫描后生成隔离提交，确认后推送")
    parser.add_argument("--gitleaks", default="gitleaks", help="Gitleaks 8.19+ 可执行文件")
    parser.add_argument("--message", default="chore: 发布插件构建与说明文档")
    parser.add_argument("--author-name", default="spumon1")
    parser.add_argument("--author-email", default="spumon1@users.noreply.github.com")
    args = parser.parse_args()
    if not re.fullmatch(r"[\w.+-]+@users\.noreply\.github\.com", args.author_email):
        parser.error("提交邮箱只接受 GitHub noreply 地址，避免带出个人邮箱")
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix="push-main-review-"))
    export = work / "export"
    export.mkdir()
    args.selected = export_worktree(root, export)
    print(f"导出 {len(args.selected)} 个白名单文本文件；审核目录：{work}")
    print("不导出账号、.env、缓存、构建产物、截图及本地提交历史；不自动同步删除。")
    args.gitleaks = shutil.which(args.gitleaks)
    if not args.gitleaks:
        raise RuntimeError("缺少 Gitleaks 8.19+；请安装或用 --gitleaks 指定路径，未推送")
    scan_tree(export, work / "initial-scan", args.gitleaks)
    print("当前发布快照扫描通过；仍需人工审核，不能据此保证绝无敏感信息。")
    if args.push:
        push_snapshot(root, work, args)
    else:
        print("仅检查结束；未创建提交、未连接远端、未推送。")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired, EOFError) as exc:
        print(f"停止：{exc}", file=sys.stderr)
        sys.exit(1)
