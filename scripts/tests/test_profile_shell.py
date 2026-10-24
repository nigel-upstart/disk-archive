"""Synthetic launcher controls, not CPU/pipeline profiling evidence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DarwinLauncherTests(unittest.TestCase):
    def launch(self, old_launcher=False):
        with tempfile.TemporaryDirectory(prefix="synthetic-profile-shell-") as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            tools = root / "tools"
            tools.mkdir()
            launcher = (ROOT / "scripts/profile.sh").read_text()
            if old_launcher:
                launcher = launcher.replace(
                    '"${clean[@]}" "$samply_bin" record --save-only -o "$run_dir/cpu.json" -- "$binary" cpu "$run_dir"',
                    '"$samply_bin" record --save-only -o "$run_dir/cpu.json" -- "${clean[@]}" "$binary" cpu "$run_dir"',
                )
            (scripts / "profile.sh").write_text(launcher)
            shutil.copy(ROOT / "scripts/profile-validate.py", scripts)
            driver = root / "synthetic-driver.py"
            driver.write_text("#!" + sys.executable + "\n" + '''import json, pathlib, sys
output = pathlib.Path(sys.argv[2])
(output / 'run.json').write_text(json.dumps(dict(schema=1,files=32,deleted=32,retained=0,rules=488,verified_downloads=32,process_spawns=0,peak_temp_bytes=1)))
''')
            driver.chmod(0o700)
            (scripts / "profile-build.py").write_text("print(" + repr(str(driver)) + ")\n")
            sampler = tools / "synthetic-samply"
            sampler.write_text("#!" + sys.executable + "\n" + '''import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
assert args[:3] == ['record', '--save-only', '-o'] and args[4] == '--'
assert pathlib.Path(args[5]).name == 'synthetic-driver.py', 'sampler must launch binary directly'
assert not any(k.startswith(('AWS_', 'DISK_ARCHIVE_', 'XDG_')) for k in os.environ), 'sampler inherited ambient providers'
assert 'RUST_LOG' not in os.environ
subprocess.run(args[5:], check=True)
pathlib.Path(args[3]).write_text(json.dumps(dict(meta={},threads=[dict(samples=dict(stack=[0]))])))
''')
            sampler.chmod(0o700)
            mise = tools / "mise"
            mise.write_text("#!/bin/sh\nprintf '%s\\n' " + repr(str(sampler)) + "\n")
            mise.chmod(0o700)
            uname = tools / "uname"
            uname.write_text("#!/bin/sh\nprintf 'Darwin\\n'\n")
            uname.chmod(0o700)
            python = tools / "python3"
            python.symlink_to(sys.executable)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.defpath,
                       AWS_SHARED_CREDENTIALS_FILE="synthetic-must-not-read",
                       DISK_ARCHIVE_BUCKET="synthetic-must-not-use", RUST_LOG="trace")
            result = subprocess.run(["bash", str(scripts / "profile.sh"), "cpu"], cwd=root,
                                    env=env, capture_output=True, text=True, timeout=20, check=False)
            return result.returncode, len(list((root / "profiles").glob("cpu-*/cpu.json")))

    def test_clean_sampler_launches_profiled_program_directly(self):
        self.assertEqual(self.launch(), (0, 1))

    def test_old_system_env_trampoline_is_rejected(self):
        status, artifacts = self.launch(old_launcher=True)
        self.assertNotEqual(status, 0)
        self.assertEqual(artifacts, 0)


if __name__ == "__main__":
    unittest.main()
