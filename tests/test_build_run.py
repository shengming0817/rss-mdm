"""Real process contracts for worktree/target ownership, not PID bookkeeping."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'hack/build_run.py'


def clean_env():
    return {k: v for k, v in os.environ.items()
            if not k.startswith(('MDM_', '_MDM_', 'SCCACHE_', 'RUSTC_', 'CARGO_BUILD_', 'GIT_'))
            and k not in ('CARGO_TARGET_DIR', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                          'MAKEFLAGS', 'MFLAGS', 'MAKELEVEL')}


class BuildRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mdm-lease-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.work = self.root / 'work tree'
        self.other = self.root / 'other'
        self.work.mkdir()
        self.other.mkdir()
        for work in (self.work, self.other):
            subprocess.run(['/usr/bin/git', 'init', '-q', str(work)], check=True, env=clean_env())
        self.pool = self.root / 'pool'
        self.env = clean_env() | {'MDM_TARGET_POOL_ROOT': str(self.pool),
                                 'MDM_TARGET_POOL_N': '2',
                                 'PYTHONPATH': str(ROOT / 'hack')}

    def run_code(self, code='pass', *, work=None, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), '--', sys.executable, '-c', code],
                              cwd=work or self.work, env=self.env | (env or {}),
                              capture_output=True, text=True, timeout=90)

    def wait_ready(self, ready, process, timeout=20):
        end = time.monotonic() + timeout
        while not ready.exists() and process.poll() is None and time.monotonic() < end:
            time.sleep(.02)
        self.assertTrue(ready.exists(), f'holder failed: {process.poll()}')

    def hold(self, *, work=None, env=None, code=None):
        ready = self.root / str(time.monotonic_ns())
        code = code or (f'import os,time; from pathlib import Path; '
                        f'Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(60)')
        process = subprocess.Popen([sys.executable, str(SCRIPT), '--', sys.executable, '-c', code],
                                   cwd=work or self.work, env=self.env | (env or {}),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, process)
        if code and 'time.sleep(60)' in code:
            self.wait_ready(ready, process)
            self.addCleanup(self.kill_group, int(ready.read_text()))
        return process

    @staticmethod
    def kill_group(pid):
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_root_and_subdirectory_share_git_worktree_identity(self):
        subprocess.run(['/usr/bin/git', 'init', '-q', str(self.work)], check=True)
        child = self.work / 'nested'; child.mkdir()
        self.hold()
        result = self.run_code(work=child)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('worktree busy', result.stderr)

    def test_pool_allocator_contention_fails_without_waiting(self):
        import fcntl
        self.assertEqual(self.run_code().returncode, 0)
        with (self.pool / '.pool.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = subprocess.run([sys.executable, str(SCRIPT), '--', 'true'], cwd=self.other,
                                    env=self.env, capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 2)
        self.assertIn('allocator busy', result.stderr)

    def test_slow_cleanup_releases_allocator_and_interruption_invalidates_owner(self):
        self.assertEqual(self.run_code(env={'MDM_TARGET_POOL_N': '1'}).returncode, 0)
        target = self.pool / 'slot-0'
        (target / 'old-artifact').touch()
        ready = self.root / 'cleaning'
        code = ("import build_run,time; from pathlib import Path; "
                "original=build_run.shutil.rmtree; "
                f"build_run.shutil.rmtree=lambda path: (Path({str(ready)!r}).touch(), time.sleep(30), original(path)); "
                "build_run.main(['--','true'])")
        process = subprocess.Popen([sys.executable, '-c', code], cwd=self.other,
                                   env=self.env | {'MDM_TARGET_POOL_N': '1'},
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, process)
        self.wait_ready(ready, process)
        # The first slot remains reserved, but allocating a different slot must not wait.
        result = self.run_code()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.pool / 'slot-0.json').exists())
        process.terminate(); process.wait(timeout=5)
        result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((target / 'old-artifact').exists())

    def test_sigquit_cancels_child_and_releases_slot(self):
        process = self.hold(env={'MDM_TARGET_POOL_N': '1'})
        process.send_signal(signal.SIGQUIT)
        self.assertEqual(process.wait(timeout=8), 128 + signal.SIGQUIT)
        result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sticky_slot_then_safe_reassignment(self):
        first = self.run_code('import os; print(os.environ["CARGO_TARGET_DIR"])',
                              env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(first.returncode, 0, first.stderr)
        target = Path(first.stdout.strip())
        (target / 'artifact').touch()
        second = self.run_code(env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertTrue((target / 'artifact').exists())
        other = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(other.returncode, 0, other.stderr)
        self.assertFalse((target / 'artifact').exists())

    def test_pool_full_and_worktree_lock_across_pool_roots(self):
        self.hold()
        repeat = self.run_code(env={'MDM_TARGET_POOL_ROOT': str(self.root / 'new-pool')})
        self.assertNotEqual(repeat.returncode, 0)
        self.assertIn('worktree busy', repeat.stderr)
        self.hold(work=self.other)
        third = self.root / 'third'; third.mkdir()
        subprocess.run(['/usr/bin/git', 'init', '-q', str(third)], check=True, env=clean_env())
        result = self.run_code(work=third)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('pool full', result.stderr)

    def test_explicit_target_and_off_still_lock(self):
        target = self.root / 'explicit'
        env = {'MDM_TARGET_POOL_N': 'off', 'CARGO_TARGET_DIR': str(target)}
        self.hold(env=env)
        self.assertFalse(self.pool.exists())
        alias = self.root / 'alias'; alias.symlink_to(target, target_is_directory=True)
        result = self.run_code(work=self.other, env=env | {'CARGO_TARGET_DIR': str(alias)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('target busy', result.stderr)
        same = self.run_code(env={'MDM_TARGET_POOL_N': 'off'})
        self.assertNotEqual(same.returncode, 0)
        self.assertIn('worktree busy', same.stderr)

    def test_case_aliases_cannot_acquire_two_target_locks(self):
        target = self.root / 'CaseTarget'; target.mkdir()
        alias = target.with_name('casetarget')
        if not alias.exists():
            # A case-sensitive volume has distinct resources, not an alias to test.
            self.skipTest('filesystem is case-sensitive')
        self.assertTrue(os.path.samefile(target, alias))
        self.hold(env={'MDM_TARGET_POOL_N': 'off', 'CARGO_TARGET_DIR': str(target)})
        result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': 'off',
                                                   'CARGO_TARGET_DIR': str(alias)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('target busy', result.stderr)

    def test_case_alias_remains_busy_after_cargo_clean_removes_target(self):
        target = self.root / 'CaseTarget'; target.mkdir()
        alias = target.with_name('casetarget')
        if not alias.exists():
            self.skipTest('filesystem is case-sensitive')
        (self.work / 'src').mkdir()
        (self.work / 'src/lib.rs').write_text('pub fn value() {}')
        (self.work / 'Cargo.toml').write_text('[package]\nname="clean-proof"\nversion="0.0.0"\nedition="2021"\n')
        ready = self.root / 'cleaned'
        code = ('import subprocess,os,time; from pathlib import Path; from build_run import lease_fds; '
                'subprocess.run(["cargo","clean","--offline"],check=True,pass_fds=lease_fds()); '
                f'Path({str(ready)!r}).write_text(str(os.getpid())); '
                'time.sleep(30)')
        process = self.hold(code=code, env={'MDM_TARGET_POOL_N': 'off', 'CARGO_TARGET_DIR': str(target)})
        self.wait_ready(ready, process)
        self.addCleanup(self.kill_group, int(ready.read_text()))
        self.assertFalse(target.exists())
        result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': 'off', 'CARGO_TARGET_DIR': str(alias)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('target busy', result.stderr)

    def test_configuration_and_exit_status(self):
        for config in ({'MDM_TARGET_POOL_N': '-1'}, {'MDM_TARGET_POOL_N': '2', 'CARGO_TARGET_DIR': '/tmp/unused'},
                       {'MDM_TARGET_POOL_N': 'off', 'CARGO_TARGET_DIR': ''}):
            with self.subTest(config=config):
                self.assertEqual(self.run_code(env=config).returncode, 2)
        result = self.run_code('import os; print(os.environ["CARGO_TARGET_DIR"]); raise SystemExit(7)',
                               env={'MDM_TARGET_POOL_N': 'off'})
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.work / 'target'))

    def test_pool_slots_cannot_be_selected_as_explicit_targets(self):
        result = self.run_code('import os; print(os.environ["CARGO_TARGET_DIR"])')
        self.assertEqual(result.returncode, 0, result.stderr)
        bypass = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': 'off',
                                                   'CARGO_TARGET_DIR': result.stdout.strip()})
        self.assertNotEqual(bypass.returncode, 0)
        self.assertIn('inside a managed pool', bypass.stderr)

    def test_defaults_four_slots_and_shrink_preserves_live_slot(self):
        code = 'from build_run import target_config; from pathlib import Path; print(target_config({},Path.cwd())[0][1])'
        self.assertEqual(self.run_code(code).stdout.strip(), '4')
        first = self.hold()
        second = self.hold(work=self.other)
        self.stop(first)
        result = self.run_code(env={'MDM_TARGET_POOL_N': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.pool / 'slot-1').exists())
        self.stop(second)
        self.assertEqual(self.run_code(env={'MDM_TARGET_POOL_N': '1'}).returncode, 0)
        self.assertFalse((self.pool / 'slot-1').exists())

    def test_invalid_lease_and_changed_target_are_rejected(self):
        for mutation in ['os.environ["_MDM_BUILD_LEASE"]="{}"',
                         'os.close(lease_fds()[0])',
                         'os.environ["CARGO_TARGET_DIR"]="/tmp/unleased"']:
            code = 'import os; from build_run import lease_fds; ' + mutation + '; lease_fds()'
            result = self.run_code(code)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid build lease', result.stderr)

    def test_real_cargo_keeps_lease_after_both_python_parents_die(self):
        (self.work / 'src').mkdir()
        (self.work / 'src/lib.rs').write_text('pub fn answer()->u8{42}')
        (self.work / 'Cargo.toml').write_text('[package]\nname="lease-kill-proof"\nversion="0.0.0"\nedition="2021"\n')
        (self.work / 'build.rs').write_text('fn main(){std::fs::write("cargo-ready","ready").unwrap(); while !std::path::Path::new("release").exists(){std::thread::sleep(std::time::Duration::from_millis(20));}}')
        middle = ('import os,subprocess; from pathlib import Path; from build_run import lease_fds; '
                  'Path("middle-pid").write_text(str(os.getpid())); '
                  'subprocess.run(["cargo","build","--offline"],check=True,pass_fds=lease_fds())')
        outer = ('import subprocess,sys; from build_run import lease_fds; '
                 f'subprocess.run([sys.executable,"-c",{middle!r}],pass_fds=lease_fds())')
        process = self.hold(code=outer, env={'MDM_TARGET_POOL_N': '1'})
        self.wait_ready(self.work / 'cargo-ready', process, timeout=60)
        middle_pid = int((self.work / 'middle-pid').read_text())
        group = os.getpgid(middle_pid)
        self.addCleanup(self.kill_group, group)
        process.kill(); process.wait(timeout=5)
        os.kill(middle_pid, signal.SIGKILL)
        os.kill(group, signal.SIGKILL)
        try:
            result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('pool full', result.stderr)
        finally:
            (self.work / 'release').touch()
        end = time.monotonic() + 15
        while time.monotonic() < end:
            result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
            if result.returncode == 0:
                break
            time.sleep(.05)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_formal_scripts_reject_missing_lease_before_starting_dependencies(self):
        scripts = ['ci.py', 't2.py', 'group-t2.py', 'backend-t2.py', 'management-t2.py',
                   'publication-t2.py', 'source-t2.py', 'apple-t2.py', 'asset-t2.py',
                   'command-t2.py', 'task-t2.py', 'identity_t2.py', 'login_gateway_t2.py']
        for script in scripts:
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, str(ROOT / 'hack' / script)],
                                        cwd=ROOT, env=clean_env() | {'CI_PLAN': '0', 'PATH': str(self.root / 'no-tools')},
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('build lease required', result.stderr)

    def test_make_entries_and_aggregate_have_one_whole_command_lease(self):
        hack = self.work / 'hack'; hack.mkdir()
        shutil.copy2(ROOT / 'Makefile', self.work / 'Makefile')
        shutil.copy2(SCRIPT, hack / 'build_run.py')
        fake = '''import json,os,sys
from pathlib import Path
from build_run import require_lease
if os.environ.get('CI_PLAN') != '1': require_lease(Path.cwd())
print(json.dumps({'name':Path(sys.argv[0]).name,'target':os.environ.get('CARGO_TARGET_DIR'),
                  'lease':os.environ.get('_MDM_BUILD_LEASE'),'plan':os.environ.get('CI_PLAN'),
                  'full':os.environ.get('CI_FULL')}))
'''
        for script in ['ci.py', 't2.py', 'group-t2.py', 'backend-t2.py', 'management-t2.py',
                       'publication-t2.py', 'source-t2.py', 'apple-t2.py', 'asset-t2.py',
                       'command-t2.py', 'task-t2.py', 'identity_t2.py']:
            (hack / script).write_text(fake)
        cargo = self.work / 'cargo'
        cargo.write_text('#!' + sys.executable + '\n' + fake)
        cargo.chmod(0o755)
        env = self.env | {'PATH': str(self.work) + os.pathsep + os.environ['PATH']}
        for target in ['build', 'check', 'test', 'ci', 'ci-full', 't2', 'source-t2',
                       't2-identity', 't2-group', 't2-backend', 't2-publication',
                       't2-assets', 't2-tasks', 't2-apple']:
            with self.subTest(target=target):
                result = subprocess.run(['make', '-s', target], cwd=self.work, env=env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                records = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(records), 9 if target == 't2' else 1)
                self.assertEqual(len({record['lease'] for record in records}), 1)
                self.assertTrue(records[0]['lease'])
                self.assertIn(str(self.pool), records[0]['target'])
                self.assertEqual(result.stderr.count('target='), 1)
        other_pool = self.root / 'preview-pool'
        result = subprocess.run(['make', '-s', 'ci-plan'], cwd=self.work,
                                env=env | {'MDM_TARGET_POOL_ROOT': str(other_pool)},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)['lease'])
        self.assertFalse(other_pool.exists())

    def test_unowned_pool_and_symlink_slot_are_not_deleted(self):
        self.pool.mkdir()
        safe = self.pool / 'keep'; safe.write_text('unowned')
        self.assertNotEqual(self.run_code().returncode, 0)
        self.assertEqual(safe.read_text(), 'unowned')
        safe.unlink()
        self.assertEqual(self.run_code().returncode, 0)
        slot = self.pool / 'slot-0'
        shutil.rmtree(slot)
        external = self.root / 'external'; external.mkdir()
        (external / 'keep').touch()
        slot.symlink_to(external, target_is_directory=True)
        self.assertNotEqual(self.run_code().returncode, 0)
        self.assertTrue((external / 'keep').exists())

    def test_signal_status_and_python_grandchild_survives_killed_parents(self):
        normal = self.hold()
        self.stop(normal)
        self.assertEqual(normal.returncode, 128 + signal.SIGTERM)
        ready = self.root / 'grandchild-ready'
        release = self.root / 'release'
        child = (f'import os,time; from pathlib import Path; Path({str(ready)!r}).write_text(str(os.getpid())); '
                 f'\nwhile not Path({str(release)!r}).exists(): time.sleep(.02)')
        middle = ('import os,subprocess,sys; from build_run import lease_fds; '
                  f'p=subprocess.Popen([sys.executable,"-c",{child!r}],pass_fds=lease_fds()); '
                  f'from pathlib import Path; Path({str(self.root / "middle")!r}).write_text(str(os.getpid())); p.wait()')
        outer = ('import subprocess,sys; from build_run import lease_fds; '
                 f'subprocess.run([sys.executable,"-c",{middle!r}],pass_fds=lease_fds())')
        process = self.hold(code=outer, env={'MDM_TARGET_POOL_N': '1'})
        self.wait_ready(ready, process)
        middle_pid = int((self.root / 'middle').read_text())
        # The direct child is a session leader; clean any orphan on assertion failure.
        group = os.getpgid(middle_pid)
        self.addCleanup(self.kill_group, group)
        process.kill(); process.wait(timeout=5)
        os.kill(middle_pid, signal.SIGKILL)
        # Also kill the direct Python child. Only its grandchild now owns the lease.
        os.kill(group, signal.SIGKILL)
        result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('pool full', result.stderr)
        release.touch()
        end = time.monotonic() + 10
        while time.monotonic() < end:
            result = self.run_code(work=self.other, env={'MDM_TARGET_POOL_N': '1'})
            if result.returncode == 0:
                break
            time.sleep(.02)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_two_real_worktrees_execute_their_own_artifacts(self):
        repo = self.root / 'repo'; repo.mkdir()
        def git(*args):
            subprocess.run(['/usr/bin/git', '-C', str(repo), *args], env=clean_env(),
                           check=True, capture_output=True)
        git('init', '-q'); git('config', 'user.email', 'lease@example.invalid'); git('config', 'user.name', 'lease test')
        (repo / 'src').mkdir()
        (repo / 'Cargo.toml').write_text('[package]\nname="lease-proof"\nversion="0.0.0"\nedition="2021"\n')
        (repo / 'src/main.rs').write_text('fn main(){println!("first");}\n#[test] fn first_api(){assert_eq!(1,1);}\n')
        git('add', '.'); git('commit', '-qm', 'first')
        second = self.root / 'second'
        git('worktree', 'add', '-qb', 'second', str(second))
        (second / 'src/main.rs').write_text('fn main(){println!("second");}\n#[test] fn second_api(){assert_eq!(2,2);}\n')
        code = '''import os,subprocess,time
from pathlib import Path
from build_run import lease_fds
Path('acquired').touch()
subprocess.run(['cargo','build','--offline'],check=True,pass_fds=lease_fds())
Path('built').touch()
end=time.monotonic()+60
while not Path(os.environ['PEER_READY']).exists():
 if time.monotonic()>end: raise RuntimeError('peer build timeout')
 time.sleep(.02)
subprocess.run([str(Path(os.environ['CARGO_TARGET_DIR'])/'debug/lease-proof')],check=True,pass_fds=lease_fds())
subprocess.run(['cargo','test','--offline'],check=True,pass_fds=lease_fds())
'''
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.run_code, code, work=repo, env={'PEER_READY': str(second / 'built')})
            end = time.monotonic() + 10
            while not (repo / 'acquired').exists() and not first.done() and time.monotonic() < end:
                time.sleep(.01)
            self.assertTrue((repo / 'acquired').exists())
            other = pool.submit(self.run_code, code, work=second, env={'PEER_READY': str(repo / 'built')})
            results = [job.result(timeout=70) for job in (first, other)]
        for label, result in zip(('first', 'second'), results):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(label + '\n', result.stdout)
            self.assertIn(f'test {label}_api ... ok', result.stdout)
            self.assertIn('1 passed; 0 failed', result.stdout)


if __name__ == '__main__':
    unittest.main()
