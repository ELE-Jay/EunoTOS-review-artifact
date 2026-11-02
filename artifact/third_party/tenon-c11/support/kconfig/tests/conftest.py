# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018 Masahiro Yamada <yamada.masahiro@socionext.com>
#

"""
Kconfig unit testing framework.

This provides fixture functions commonly used from test files.
"""

import os
import pytest
import shutil
import subprocess
import tempfile

def pytest_addoption(parser):
    parser.addoption("--BASE_PATH")

class Conf:
    """Kconfig runner and result checker.

    This class provides methods to run text-based interface of Kconfig
    (scripts/kconfig/conf) and retrieve the resulted configuration,
    stdout, and stderr.  It also provides methods to compare those
    results with expectations.
    """

    def __init__(self, request):
        """Create a new Conf instance.

        request: object to introspect the requesting test module
        """
        # the directory of the test being run
        self._test_dir = os.path.dirname(str(request.fspath))
        self.CONF_PATH = os.path.join(request.config.getoption("--BASE_PATH"),\
                                       'build', 'kconfig', 'conf')

    # runners
    def _run_conf(self, mode, dot_config=None, out_file='.config',
                  interactive=False, in_keys=None, extra_env={}):
        """Run text-based Kconfig executable and save the result.

        mode: input mode option (--oldaskconfig, --defconfig=<file> etc.)
        dot_config: .config file to use for configuration base
        out_file: file name to contain the output config data
        interactive: flag to specify the interactive mode
        in_keys: key inputs for interactive modes
        extra_env: additional environments
        returncode: exit status of the Kconfig executable
        """
        command = [self.CONF_PATH, mode, 'Kconfig']

        # Override 'srctree' environment to make the test as the top directory
        extra_env['srctree'] = self._test_dir

        # Run Kconfig in a temporary directory.
        # This directory is automatically removed when done.
        with tempfile.TemporaryDirectory() as temp_dir:

            # if .config is given, copy it to the working directory
            if dot_config:
                shutil.copyfile(os.path.join(self._test_dir, dot_config),
                                os.path.join(temp_dir, '.config'))

            if 'KCONFIG_EXTEND_AUTOCONFIG' in extra_env:
                extend_config = extra_env['KCONFIG_EXTEND_AUTOCONFIG']
                extra_env['KCONFIG_EXTEND_AUTOCONFIG'] = \
                    os.path.join(temp_dir, extra_env['KCONFIG_EXTEND_AUTOCONFIG'])

            if 'KCONFIG_EXTEND_AUTOHEADER' in extra_env:
                extend_autoconf = extra_env['KCONFIG_EXTEND_AUTOHEADER']
                extra_env['KCONFIG_EXTEND_AUTOHEADER'] = \
                    os.path.join(temp_dir, extra_env['KCONFIG_EXTEND_AUTOHEADER'])

            if 'KCONFIG_EXTEND_TEMPLATE' in extra_env:
                extra_env['KCONFIG_EXTEND_TEMPLATE'] = \
                    os.path.join(self._test_dir, extra_env['KCONFIG_EXTEND_TEMPLATE'])

            ps = subprocess.Popen(command,
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  cwd=temp_dir,
                                  env=dict(os.environ, **extra_env))

            # If input key sequence is given, feed it to stdin.
            if in_keys:
                ps.stdin.write(in_keys.encode('utf-8'))

            while ps.poll() is None:
                # For interactive modes such as oldaskconfig, oldconfig,
                # send 'Enter' key until the program finishes.
                if interactive:
                    ps.stdin.write(b'\n')

            self.retcode = ps.returncode
            self.stdout = ps.stdout.read().decode()
            self.stderr = ps.stderr.read().decode()

            # Retrieve the resulted config data only when .config is supposed
            # to exist.  If the command fails, the .config does not exist.
            # 'listnewconfig' does not produce .config in the first place.
            if self.retcode == 0 and out_file:
                with open(os.path.join(temp_dir, out_file)) as f:
                    self.config = f.read()
            else:
                self.config = None

            if self.retcode == 0 and 'KCONFIG_EXTEND_CONFIG_ENABLE' in extra_env \
            and extra_env['KCONFIG_EXTEND_CONFIG_ENABLE']== 'y':
                if 'KCONFIG_EXTEND_TEMPLATE' not in extra_env \
                or os.path.exists(extra_env['KCONFIG_EXTEND_TEMPLATE']):
                    if 'KCONFIG_EXTEND_AUTOCONFIG' in extra_env:
                        with open(extra_env['KCONFIG_EXTEND_AUTOCONFIG']) as f:
                            self.extend_config = f.read()
                    else:
                        extend_config='.extend.config'
                        with open(os.path.join(temp_dir, 'include/config/.extend.config')) as f:
                            self.extend_config = f.read()
                    if 'KCONFIG_EXTEND_AUTOHEADER' in extra_env:
                        with open(extra_env['KCONFIG_EXTEND_AUTOHEADER']) as f:
                            self.extend_autoconf = f.read()
                    else:
                        extend_autoconf='extend_autoconf.h'
                        with open(os.path.join(temp_dir, 'include/config/extend_autoconf.h')) as f:
                            self.extend_autoconf = f.read()
                else:
                    self.extend_config = None
                    self.extend_autoconf = None

        # Logging:
        # Pytest captures the following information by default.  In failure
        # of tests, the captured log will be displayed.  This will be useful to
        # figure out what has happened.

        print("[command]\n{}\n".format(' '.join(command)))

        print("[retcode]\n{}\n".format(self.retcode))

        print("[stdout]")
        print(self.stdout)

        print("[stderr]")
        print(self.stderr)

        if self.config is not None:
            print("[output for '{}']".format(out_file))
            print(self.config)

        if self.extend_config is not None:
            print("[output for '{}']".format(extend_config))
            print(self.extend_config)

        if self.extend_autoconf is not None:
            print("[output for '{}']".format(extend_autoconf))
            print(self.extend_autoconf)

        return self.retcode


    def build_extend_config(self, mode,extend_config=None, extend_autoconf=None,
                            dot_config=None, in_keys=None):
        extra_env = {'KCONFIG_EXTEND_NAME':'EXTEND',
                     'KCONFIG_EXTEND_CONFIG_ENABLE':'y'}
        if extend_config is not None:
            extra_env['KCONFIG_EXTEND_AUTOCONFIG'] = extend_config
        if extend_autoconf is not None:
            extra_env['KCONFIG_EXTEND_AUTOHEADER'] = extend_autoconf
        return self._run_conf(mode=mode, dot_config=dot_config,
                              interactive=True, in_keys=in_keys,
                              extra_env=extra_env)

    def render_extend_config(self, mode,extend_template=None,
                            dot_config=None, in_keys=None):
        extra_env = {'KCONFIG_EXTEND_NAME':'EXTEND',
                     'KCONFIG_EXTEND_CONFIG_ENABLE':'y'
                     }
        if extend_template is not None:
            extra_env['KCONFIG_EXTEND_TEMPLATE'] = extend_template
        return self._run_conf(mode=mode, dot_config=dot_config,
                              interactive=True, in_keys=in_keys,
                              extra_env=extra_env)

    def oldaskconfig(self, dot_config=None, in_keys=None):
        """Run oldaskconfig.

        dot_config: .config file to use for configuration base (optional)
        in_key: key inputs (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._run_conf('--oldaskconfig', dot_config=dot_config,
                              interactive=True, in_keys=in_keys)

    def oldconfig(self, dot_config=None, in_keys=None):
        """Run oldconfig.

        dot_config: .config file to use for configuration base (optional)
        in_key: key inputs (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._run_conf('--oldconfig', dot_config=dot_config,
                              interactive=True, in_keys=in_keys)

    def olddefconfig(self, dot_config=None):
        """Run olddefconfig.

        dot_config: .config file to use for configuration base (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._run_conf('--olddefconfig', dot_config=dot_config)

    def defconfig(self, defconfig):
        """Run defconfig.

        defconfig: defconfig file for input
        returncode: exit status of the Kconfig executable
        """
        defconfig_path = os.path.join(self._test_dir, defconfig)
        return self._run_conf('--defconfig={}'.format(defconfig_path))

    def _allconfig(self, mode, all_config):
        if all_config:
            all_config_path = os.path.join(self._test_dir, all_config)
            extra_env = {'KCONFIG_ALLCONFIG': all_config_path}
        else:
            extra_env = {}

        return self._run_conf('--{}config'.format(mode), extra_env=extra_env)

    def allyesconfig(self, all_config=None):
        """Run allyesconfig.

        all_config: fragment config file for KCONFIG_ALLCONFIG (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._allconfig('allyes', all_config)

    def allmodconfig(self, all_config=None):
        """Run allmodconfig.

        all_config: fragment config file for KCONFIG_ALLCONFIG (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._allconfig('allmod', all_config)

    def allnoconfig(self, all_config=None):
        """Run allnoconfig.

        all_config: fragment config file for KCONFIG_ALLCONFIG (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._allconfig('allno', all_config)

    def alldefconfig(self, all_config=None):
        """Run alldefconfig.

        all_config: fragment config file for KCONFIG_ALLCONFIG (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._allconfig('alldef', all_config)

    def randconfig(self, all_config=None):
        """Run randconfig.

        all_config: fragment config file for KCONFIG_ALLCONFIG (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._allconfig('rand', all_config)

    def savedefconfig(self, dot_config):
        """Run savedefconfig.

        dot_config: .config file for input
        returncode: exit status of the Kconfig executable
        """
        return self._run_conf('--savedefconfig', out_file='defconfig')

    def listnewconfig(self, dot_config=None):
        """Run listnewconfig.

        dot_config: .config file to use for configuration base (optional)
        returncode: exit status of the Kconfig executable
        """
        return self._run_conf('--listnewconfig', dot_config=dot_config,
                              out_file=None)

    # checkers
    def _read_and_compare(self, compare, expected):
        """Compare the result with expectation.

        compare: function to compare the result with expectation
        expected: file that contains the expected data
        """
        with open(os.path.join(self._test_dir, expected)) as f:
            expected_data = f.read()
        return compare(self, expected_data)

    def _contains(self, attr, expected):
        return self._read_and_compare(
                                    lambda s, e: getattr(s, attr).find(e) >= 0,
                                    expected)

    def _matches(self, attr, expected):
        return self._read_and_compare(lambda s, e: getattr(s, attr) == e,
                                      expected)

    def config_contains(self, expected):
        """Check if resulted configuration contains expected data.

        expected: file that contains the expected data
        returncode: True if result contains the expected data, False otherwise
        """
        return self._contains('config', expected)

    def config_matches(self, expected):
        """Check if resulted configuration exactly matches expected data.

        expected: file that contains the expected data
        returncode: True if result matches the expected data, False otherwise
        """
        return self._matches('config', expected)

    def stdout_contains(self, expected):
        """Check if resulted stdout contains expected data.

        expected: file that contains the expected data
        returncode: True if result contains the expected data, False otherwise
        """
        return self._contains('stdout', expected)

    def stdout_matches(self, expected):
        """Check if resulted stdout exactly matches expected data.

        expected: file that contains the expected data
        returncode: True if result matches the expected data, False otherwise
        """
        return self._matches('stdout', expected)

    def stderr_contains(self, expected):
        """Check if resulted stderr contains expected data.

        expected: file that contains the expected data
        returncode: True if result contains the expected data, False otherwise
        """
        return self._contains('stderr', expected)

    def stderr_matches(self, expected):
        """Check if resulted stderr exactly matches expected data.

        expected: file that contains the expected data
        returncode: True if result matches the expected data, False otherwise
        """
        return self._matches('stderr', expected)



    def extend_config_contains(self, expected):
        """Check if resulted extend configuration contains expected data.

        expected: file that contains the expected data
        returncode: True if result contains the expected data, False otherwise
        """
        return self._contains('extend_config', expected)

    def extend_config_matches(self, expected):
        """Check if resulted extend configuration exactly matches expected data.

        expected: file that contains the expected data
        returncode: True if result matches the expected data, False otherwise
        """
        return self._matches('extend_config', expected)

    def extend_autoconf_contains(self, expected):
        """Check if resulted extend configuration contains expected data.

        expected: file that contains the expected data
        returncode: True if result contains the expected data, False otherwise
        """
        return self._contains('extend_autoconf', expected)

    def extend_autoconf_matches(self, expected):
        """Check if resulted extend configuration exactly matches expected data.

        expected: file that contains the expected data
        returncode: True if result matches the expected data, False otherwise
        """
        return self._matches('extend_autoconf', expected)

@pytest.fixture(scope="module")
def conf(request):
    """Create a Conf instance and provide it to test functions."""
    return Conf(request)
