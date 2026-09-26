"""推送脚本只在临时本地仓库对戏，不碰 GitHub 的真柜台。"""

import argparse
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import push_main as publish


class SafetyTests(unittest.TestCase):
    def test_auth_error_names_operation_without_leaking_stderr(self):
        result = subprocess.CompletedProcess([], 128, b"", b"fatal: could not read Username: private-value")
        with patch.object(publish.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as caught:
                publish.command(["git", "-C", "/tmp", "push", "origin", "HEAD:main"], Path("/tmp"))
        self.assertIn("git push", str(caught.exception))
        self.assertIn("gh auth login", str(caught.exception))
        self.assertNotIn("private-value", str(caught.exception))

    def test_unknown_git_error_does_not_echo_raw_output(self):
        result = subprocess.CompletedProcess([], 128, b"", b"unexpected secret-value")
        with patch.object(publish.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError) as caught:
                publish.command(["git", "clone", "example"], Path("/tmp"))
        self.assertIn("git clone", str(caught.exception))
        self.assertNotIn("secret-value", str(caught.exception))

    def test_auth_environment_survives_but_repository_overrides_do_not(self):
        values = {"GIT_ASKPASS": "/tmp/askpass", "GIT_SSH_COMMAND": "ssh -F /tmp/config",
                  "GIT_DIR": "/tmp/unrelated", "GIT_INDEX_FILE": "/tmp/index",
                  "GITLEAKS_CONFIG": "/tmp/ignore-all"}
        with patch.dict(publish.os.environ, values), \
                patch.object(publish.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
            publish.command(["git", "status"], Path("/tmp"))
        env = run.call_args.kwargs["env"]
        self.assertEqual(values["GIT_ASKPASS"], env.get("GIT_ASKPASS"))
        self.assertEqual(values["GIT_SSH_COMMAND"], env.get("GIT_SSH_COMMAND"))
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_INDEX_FILE", env)
        self.assertNotIn("GITLEAKS_CONFIG", env)
        self.assertEqual("0", env.get("GIT_TERMINAL_PROMPT"))

    def test_allowlist_excludes_private_files_and_binary_assets(self):
        for name in [".env", "gpt/codex-user.json", "go/codex-user.json",
                     "build/plugin.so", "design/screenshot.png", ".codex/config.toml",
                     ".github/workflows/.env", "scripts/secret.pem"]:
            self.assertFalse(publish.allowed(name), name)
        for name in ["README.md", "go/main.go", "go/unified_bank.json",
                     ".github/workflows/build-plugin.yml", "scripts/push_main.py"]:
            self.assertTrue(publish.allowed(name), name)

    def test_symlink_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "alias").symlink_to(root, target_is_directory=True)
            for name in ["../outside", "/outside", ".git/config", "alias/a.py"]:
                with self.assertRaises(RuntimeError):
                    publish.safe_path(root, name)

    def test_unknown_private_key_is_rejected(self):
        raw = ("-----BEGIN " + "PRIVATE KEY-----\nfake\n-----END "
               + "PRIVATE KEY-----").encode()
        with self.assertRaisesRegex(RuntimeError, "私钥"):
            publish.scan_text("go/main.go", raw)

    def test_known_fixture_is_only_accepted_at_exact_path_and_hash(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / publish.FIXTURE_PATH).read_text()
        key = publish.PRIVATE_KEY.search(text)[0]
        self.assertIn("TEST_TLS_FIXTURE", publish.scan_text(publish.FIXTURE_PATH, key.encode()))
        for name, data in [("scripts/private.py", key), (publish.FIXTURE_PATH, key.replace("\n", "\nX", 1))]:
            with self.assertRaises(RuntimeError):
                publish.scan_text(name, data.encode())

    def test_personal_email_is_blocked_without_echo(self):
        address = "person@" + "gmail" + ".com"
        with self.assertRaises(RuntimeError) as caught:
            publish.scan_text("README.md", address.encode())
        self.assertNotIn(address, str(caught.exception))

    def test_binary_is_not_silently_skipped(self):
        with self.assertRaises(RuntimeError):
            publish.scan_text("go/main.go", b"text\0secret")

    def test_scanner_error_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "export"
            source.mkdir()
            (source / "README.md").write_text("plain text")
            with patch.object(publish, "command", side_effect=RuntimeError("scanner failure")):
                with self.assertRaisesRegex(RuntimeError, "扫描未通过"):
                    publish.scan_tree(source, root / "scan", "gitleaks")

    def test_default_mode_does_not_push(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake_file = root / "scripts" / "push_main.py"
            with patch.object(publish, "__file__", str(fake_file)), \
                    patch.object(publish, "export_worktree", return_value=["README.md"]), \
                    patch.object(publish, "scan_tree"), \
                    patch.object(publish.shutil, "which", return_value="gitleaks"), \
                    patch.object(publish, "push_snapshot") as push, \
                    patch("sys.argv", ["push_main.py"]), redirect_stdout(io.StringIO()):
                publish.main()
            push.assert_not_called()


class IsolatedGitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.local = self.root / "local"
        self.run_git(self.root, "init", "--bare", "--initial-branch=main", str(self.remote))
        self.run_git(self.root, "init", "--initial-branch=main", str(self.local))
        (self.local / "README.md").write_text("public baseline\n")
        self.run_git(self.local, "add", "README.md")
        self.run_git(self.local, "commit", "-m", "baseline")
        self.run_git(self.local, "remote", "add", "origin", str(self.remote))
        self.run_git(self.local, "push", "origin", "main")
        self.base = self.run_git(self.remote, "rev-parse", "main").strip()
        # 本地新增提交必须留在本地，发布不能把它当嫁妆一起送出去。
        (self.local / "README.md").write_text("local-only historical content\n")
        self.run_git(self.local, "commit", "-am", "local-only history")
        self.local_head = self.run_git(self.local, "rev-parse", "HEAD").strip()
        (self.local / "README.md").write_text("reviewed current content\n")
        self.work = self.root / "review"
        (self.work / "export").mkdir(parents=True)
        selected = publish.export_worktree(self.local, self.work / "export")
        self.args = argparse.Namespace(selected=selected, gitleaks="fake-scanner",
                                       author_name="Test", author_email="test@users.noreply.github.com",
                                       message="chore: 测试隔离推送")

    def run_git(self, cwd, *args):
        return subprocess.check_output(["git", "-c", "user.name=Test",
                                        "-c", "user.email=test@users.noreply.github.com",
                                        "-c", "core.hooksPath=/dev/null", *args],
                                       cwd=cwd, stderr=subprocess.DEVNULL).decode()

    def invoke(self, answer, scanner=None):
        with patch.object(publish, "REMOTE_URLS", {str(self.remote)}), \
                patch.object(publish, "scan_tree", side_effect=scanner), \
                patch("builtins.input", return_value=answer), redirect_stdout(io.StringIO()):
            publish.push_snapshot(self.local, self.work, self.args)

    def test_cancel_does_not_change_remote_or_local_branch(self):
        self.invoke("cancel")
        self.assertEqual(self.base, self.run_git(self.remote, "rev-parse", "main").strip())
        self.assertEqual(self.local_head, self.run_git(self.local, "rev-parse", "HEAD").strip())
        self.assertEqual("reviewed current content\n", (self.local / "README.md").read_text())

    def test_confirmation_pushes_one_snapshot_without_local_history(self):
        self.invoke("PUSH main")
        head = self.run_git(self.remote, "rev-parse", "main").strip()
        self.assertEqual(self.base, self.run_git(self.remote, "rev-parse", "main^").strip())
        self.assertNotEqual(self.local_head, head)
        self.assertEqual("reviewed current content\n", self.run_git(self.remote, "show", "main:README.md"))
        self.assertEqual("2", self.run_git(self.remote, "rev-list", "--count", "main").strip())

    def test_failed_final_scan_prevents_push(self):
        with self.assertRaisesRegex(RuntimeError, "detected"):
            self.invoke("PUSH main", scanner=RuntimeError("detected"))
        self.assertEqual(self.base, self.run_git(self.remote, "rev-parse", "main").strip())

    def test_final_scan_includes_committed_content_and_metadata(self):
        def inspect(source, _work, _scanner):
            self.assertEqual("reviewed current content\n", (source / "README.md").read_text())
            metadata = (source / ".push-main-commit-metadata.txt").read_text()
            self.assertIn(self.args.message, metadata)
            self.assertIn(self.args.author_email, metadata)
        self.invoke("cancel", scanner=inspect)

    def test_unexpected_origin_is_rejected(self):
        with patch.object(publish, "REMOTE_URLS", set()):
            with self.assertRaisesRegex(RuntimeError, "origin"):
                publish.push_snapshot(self.local, self.work, self.args)

    def test_failed_push_preflight_does_not_ask_for_confirmation(self):
        real_git = publish.git
        def checked_git(root, *args):
            if "push" in args:
                self.assertIn("--dry-run", args)
                raise RuntimeError("authentication unavailable")
            return real_git(root, *args)
        with patch.object(publish, "REMOTE_URLS", {str(self.remote)}), \
                patch.object(publish, "scan_tree"), patch.object(publish, "git", side_effect=checked_git), \
                patch("builtins.input") as prompt, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "authentication unavailable"):
                publish.push_snapshot(self.local, self.work, self.args)
        prompt.assert_not_called()
        self.assertEqual(self.base, self.run_git(self.remote, "rev-parse", "main").strip())

    def test_concurrent_remote_update_is_not_overwritten(self):
        def advance_remote(_prompt):
            self.run_git(self.local, "commit", "-am", "advance remote")
            self.run_git(self.local, "push", "origin", "main")
            return "PUSH main"
        with patch.object(publish, "REMOTE_URLS", {str(self.remote)}), \
                patch.object(publish, "scan_tree"), \
                patch("builtins.input", side_effect=advance_remote), redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                publish.push_snapshot(self.local, self.work, self.args)
        self.assertEqual(self.run_git(self.local, "rev-parse", "HEAD"),
                         self.run_git(self.remote, "rev-parse", "main"))


if __name__ == "__main__":
    unittest.main()
