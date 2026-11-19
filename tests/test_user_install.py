"""Installation per user: defaults in the home directory, check hints, install.sh/uninstall.sh."""
import io
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from helpers import ROOT, TOKEN, fixture
from mavirank_collector import cli
from mavirank_collector.config import (ConfigError, default_config_path, default_state_dir, load_config,
                                       missing_config_hint, user_config_path, user_state_dir)

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class DefaultsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.env = {"HOME": self.home}

    def write_user_config(self, env=None):
        path = user_config_path(env or self.env)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"[mavirank]\ningest_url = https://x.example/api/v1/ingest\ntoken = {TOKEN}\n"
                     f"[logs]\naccess_log = /x\n")
        return path

    def test_user_paths_follow_home_and_xdg(self):
        self.assertEqual(user_config_path(self.env),
                         os.path.join(self.home, ".config", "mavirank-collector", "collector.conf"))
        self.assertEqual(user_state_dir(self.env), os.path.join(self.home, ".local", "state", "mavirank-collector"))
        env = dict(self.env, XDG_CONFIG_HOME="/srv/cfg", XDG_STATE_HOME="/srv/state")
        self.assertEqual(user_config_path(env), "/srv/cfg/mavirank-collector/collector.conf")
        self.assertEqual(user_state_dir(env), "/srv/state/mavirank-collector")
        env = dict(self.env, XDG_CONFIG_HOME="relative/cfg", XDG_STATE_HOME="")  # ignored as per XDG spec
        self.assertTrue(user_config_path(env).startswith(self.home + os.sep))
        self.assertTrue(user_state_dir(env).startswith(self.home + os.sep))

    def test_config_in_home_with_fallback_to_older_system_file(self):
        path = user_config_path(self.env)
        legacy = os.path.join(self.home, "etc-collector.conf")
        with mock.patch("mavirank_collector.config.SYSTEM_CONFIG_PATH", legacy):
            self.assertEqual(default_config_path(self.env), path)  # nothing exists: the home path
            with open(legacy, "w", encoding="utf-8") as fh:
                fh.write("[logs]\naccess_log = /x\n")
            self.assertEqual(default_config_path(self.env), legacy)  # only the older file exists
            self.write_user_config()
            self.assertEqual(default_config_path(self.env), path)  # the home file wins

    def test_state_dir_defaults_to_home(self):
        self.assertEqual(default_state_dir(self.env), user_state_dir(self.env))
        env = dict(self.env, XDG_STATE_HOME="/var/lib")  # as set in the container image
        self.assertEqual(default_state_dir(env), "/var/lib/mavirank-collector")
        path = self.write_user_config()
        self.assertEqual(load_config(path, environ=self.env).state_dir, user_state_dir(self.env))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("[state]\ndir = /srv/collector-state\n")
        self.assertEqual(load_config(path, environ=self.env).state_dir, "/srv/collector-state")

    def test_missing_default_config_names_the_installer(self):
        self.assertEqual(missing_config_hint("/elsewhere.conf", self.env), "")
        with self.assertRaises(ConfigError) as ctx:
            load_config(user_config_path(self.env), environ=self.env)
        self.assertIn("install.sh", str(ctx.exception))
        with self.assertRaises(ConfigError) as ctx:
            load_config(os.path.join(self.home, "missing.conf"), environ=self.env)
        self.assertNotIn("install.sh", str(ctx.exception))

    def test_parser_prefers_environment_variable(self):
        with mock.patch.dict(os.environ, {"MAVIRANK_COLLECTOR_CONFIG": "/from/env.conf"}):
            self.assertEqual(cli.build_parser().parse_args(["check"]).config, "/from/env.conf")
            self.assertEqual(cli.build_parser().parse_args(["--config", "/x.conf", "check"]).config, "/x.conf")
        path = self.write_user_config()
        env = {k: v for k, v in os.environ.items() if k not in ("MAVIRANK_COLLECTOR_CONFIG", "XDG_CONFIG_HOME")}
        env["HOME"] = self.home
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(cli.build_parser().parse_args(["check"]).config, path)


class _Resp:
    date = None


class _Client:
    def get_config(self, etag):  # noqa: ARG002
        return _Resp(), {"hostnames": ["example.com"], "configVersion": "1"}


@unittest.skipIf(IS_ROOT, "root reads every file; the permission hints cannot be produced")
class CheckHintsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = os.path.join(self.tmp.name, "access.log")
        shutil.copy(fixture("access.log"), self.log)
        self.private = os.path.join(self.tmp.name, "private")
        os.makedirs(self.private)
        shutil.copy(fixture("access.log"), os.path.join(self.private, "access.log"))
        self.conf = os.path.join(self.tmp.name, "collector.conf")
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write(f"[mavirank]\ningest_url = https://x.example/api/v1/ingest\ntoken = {TOKEN}\n"
                     f"[logs]\naccess_log = {self.log}, {self.private}/*.log\ndomain = example.com\n"
                     f"[state]\ndir = {self.tmp.name}/state\n[bots]\nverify = false\n")
        os.chmod(self.conf, 0o600)
        self.addCleanup(os.chmod, self.private, 0o700)
        self.addCleanup(os.chmod, self.log, 0o600)

    def check(self, root=False):
        out = io.StringIO()
        with mock.patch.object(cli, "is_root", return_value=root):
            code = cli.cmd_check(self.conf, out, client=_Client())
        return code, out.getvalue()

    def test_all_readable(self):
        code, text = self.check()
        self.assertEqual(code, 0, text)
        self.assertNotIn("this process runs as", text)

    def test_unreadable_file_names_owner_mode_and_identity(self):
        os.chmod(self.log, 0)
        code, text = self.check()
        self.assertNotEqual(code, 0)
        self.assertIn(f"{self.log} not readable (permission denied): file owner ", text)
        self.assertIn("mode 000", text)
        self.assertIn(f"this process runs as uid {os.geteuid()} (", text)
        code, text = self.check(root=True)  # message as before when running as root
        self.assertIn("add the user to the group of the log files (adm)", text)
        self.assertNotIn("this process runs as", text)

    def test_closed_directory_is_named(self):
        os.chmod(self.private, 0)
        code, text = self.check()
        self.assertIn("[WARN] access_log: no file matches", text)
        self.assertIn(f"directory {self.private} cannot be entered", text)
        _, text = self.check(root=True)  # no new warning when running as root
        self.assertNotIn("no file matches", text)


CRONTAB_MOCK = """#!/bin/sh
F="$HOME/.crontab-mock"
case "$1" in
  -l) [ -f "$F" ] || { echo "no crontab for test" >&2; exit 1; }; cat "$F" ;;
  -r) rm -f "$F" ;;
  -) cat > "$F" ;;
  *) cat "$1" > "$F" ;;
esac
"""


@unittest.skipIf(shutil.which("sh") is None, "needs sh")
class InstallUserScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.home)
        os.makedirs(bindir)
        crontab = os.path.join(bindir, "crontab")
        with open(crontab, "w", encoding="utf-8") as fh:
            fh.write(CRONTAB_MOCK)
        os.chmod(crontab, 0o755)
        self.env = {"HOME": self.home, "PATH": bindir + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
                    "TMPDIR": self.tmp.name}

    def sh(self, *args):
        return subprocess.run(["sh", *args], cwd=self.tmp.name, env=self.env, capture_output=True, text=True,
                              timeout=60)

    def crontab(self):
        path = os.path.join(self.home, ".crontab-mock")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def mode(self, *parts):
        return stat.S_IMODE(os.stat(os.path.join(self.home, *parts)).st_mode)

    def test_install_run_uninstall(self):
        with open(os.path.join(self.home, ".crontab-mock"), "w", encoding="utf-8") as fh:
            fh.write("0 3 * * * /usr/bin/true\n")
        install, uninstall = os.path.join(ROOT, "install.sh"), os.path.join(ROOT, "uninstall.sh")
        first = self.sh(install, "--python", shutil.which("python3") or "python3")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("run --dry-run", first.stdout)
        self.assertIn("*/5 * * * *", first.stdout)
        self.assertEqual(self.crontab(), "0 3 * * * /usr/bin/true\n")  # only printed
        conf = os.path.join(self.home, ".config", "mavirank-collector", "collector.conf")
        state = os.path.join(self.home, ".local", "state", "mavirank-collector")
        self.assertEqual(self.mode(".config", "mavirank-collector"), 0o700)
        self.assertEqual(self.mode(".config", "mavirank-collector", "collector.conf"), 0o600)
        self.assertEqual(self.mode(".local", "state", "mavirank-collector"), 0o700)
        with open(conf, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"\ndir = {state}\n", text)
        self.assertNotIn("dir = /var/lib", text)

        with open(conf, "a", encoding="utf-8") as fh:
            fh.write("# edited\n")
        for _ in range(2):
            again = self.sh(install, "--cron")
            self.assertEqual(again.returncode, 0, again.stderr)
        with open(conf, encoding="utf-8") as fh:
            self.assertTrue(fh.read().endswith("# edited\n"))  # never overwritten
        table = self.crontab()
        self.assertTrue(table.startswith("0 3 * * * /usr/bin/true\n"))
        self.assertEqual(table.count("mavirank-collector' run"), 1)

        # the command works with the offline dry run against the fixture logs
        dry = subprocess.run([os.path.join(self.home, ".local", "bin", "mavirank-collector"),
                              "--config", fixture("dry-run.conf"), "run", "--dry-run", "--offline", "--samples", "0"],
                             cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("DRY RUN", dry.stdout)

        removed = self.sh(uninstall)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertEqual(self.crontab(), "0 3 * * * /usr/bin/true\n")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "mavirank-collector")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "share", "mavirank-collector")))
        self.assertTrue(os.path.exists(conf))
        purged = self.sh(uninstall, "--purge")
        self.assertEqual(purged.returncode, 0, purged.stderr)
        self.assertFalse(os.path.exists(conf))
        self.assertFalse(os.path.exists(state))

    def test_two_named_instances_side_by_side(self):
        install, uninstall = os.path.join(ROOT, "install.sh"), os.path.join(ROOT, "uninstall.sh")
        for args in (["--cron"], ["--name", "shop", "--cron"], ["--name", "blog", "--cron"], ["--name", "shop", "--cron"]):
            result = self.sh(install, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
        conf_dir = os.path.join(self.home, ".config", "mavirank-collector")
        state = os.path.join(self.home, ".local", "state", "mavirank-collector")
        self.assertEqual(sorted(os.listdir(conf_dir)), ["blog.conf", "collector.conf", "shop.conf"])
        with open(os.path.join(conf_dir, "shop.conf"), encoding="utf-8") as fh:
            self.assertIn(f"\ndir = {state}/shop\n", fh.read())
        table = self.crontab()
        self.assertEqual(len(table.splitlines()), 3)
        self.assertIn(f"--config '{conf_dir}/shop.conf' run", table)
        self.assertIn("# mavirank-collector:blog (install.sh)", table)
        self.assertEqual(self.sh(install, "--name", "Bad").returncode, 1)
        self.assertEqual(self.sh(install, "--name", "Bad_name").returncode, 1)
        self.assertEqual(self.sh(install, "--name", "keys").returncode, 1)

        # the default instance cannot remove the shared command while named instances run
        removed = self.sh(uninstall, "--purge")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.home, ".local", "bin", "mavirank-collector")))
        self.assertEqual(sorted(os.listdir(conf_dir)), ["blog.conf", "shop.conf"])
        self.assertEqual(sorted(os.listdir(state)), ["blog", "shop"])
        removed = self.sh(uninstall, "--name", "shop", "--purge")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertEqual(os.listdir(conf_dir), ["blog.conf"])
        self.assertEqual(os.listdir(state), ["blog"])
        self.assertNotIn(":shop", self.crontab())
        self.assertIn(":blog", self.crontab())
        self.sh(uninstall, "--name", "blog")
        self.assertIsNone(self.crontab())
        removed = self.sh(uninstall)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "mavirank-collector")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "share", "mavirank-collector")))
        self.assertTrue(os.path.exists(os.path.join(conf_dir, "blog.conf")))  # not purged

    def test_root_is_warned_but_not_refused(self):
        fake_id = os.path.join(self.env["PATH"].split(os.pathsep)[0], "id")
        with open(fake_id, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\n[ "$1" = "-u" ] && { echo 0; exit 0; }\necho root\n')
        os.chmod(fake_id, 0o755)
        result = self.sh(os.path.join(ROOT, "install.sh"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("installing as root", result.stderr)
        self.assertIn("installing as root", result.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.home, ".config", "mavirank-collector", "collector.conf")))
        self.assertEqual(self.sh(os.path.join(ROOT, "uninstall.sh"), "--purge").returncode, 0)

    def test_rejects_old_python(self):
        fake = os.path.join(self.tmp.name, "python-old")
        with open(fake, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\n[ "$1" = "-V" ] && { echo "Python 3.6.8"; exit 0; }\nexit 1\n')
        os.chmod(fake, 0o755)
        result = self.sh(os.path.join(ROOT, "install.sh"), "--python", fake)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Python >= 3.9 is required", result.stderr)
        self.assertIn("3.6.8", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local")))


if __name__ == "__main__":
    unittest.main()
