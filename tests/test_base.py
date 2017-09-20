#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2015 SUSE Linux GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals

import imp
import mock
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


# NOTE(toabctl): Hack to import non-module file for testing
sv = imp.load_source("renderspec", "renderspec")


RENDERSPEC_EXECUTABLE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../', 'renderspec')
)


class RenderspecBaseTest(unittest.TestCase):
    """Basic test class. Other tests should use this one"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix='obs-service-renderspec-test-')
        os.chdir(self._tmpdir)

    def _run_renderspec(self, params=[]):
        self._tmpoutdir = tempfile.mkdtemp(
            prefix='obs-service-renderspec-test-outdir-')
        cmd = [sys.executable,
               RENDERSPEC_EXECUTABLE,
               '--outdir', self._tmpoutdir] + params
        try:
            subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, env=os.environ.copy())
            for f in os.listdir(self._tmpoutdir):
                os.unlink(self._tmpdir+"/"+f)
                # FIXME: in most modes the files get not replaced,
                # but store in parallel with _service: prefix
                shutil.move(self._tmpoutdir+"/"+f, self._tmpdir)
            shutil.rmtree(self._tmpoutdir)
        except subprocess.CalledProcessError as e:
            raise Exception(
                "Can not call '%s' in dir '%s'. Error: %s" % (" ".join(cmd),
                                                              self._tmpdir,
                                                              e.output))

    def tearDown(self):
        shutil.rmtree(self._tmpdir)


class RenderspecBasics(RenderspecBaseTest):
    def _write_template(self, name):
        """write a template which can be rendered"""
        with open(os.path.join(self._tmpdir, name), 'w+') as f:
            f.write("""
Name: test
License: Apache-2.0
Version: 1.1.0
Release: 0
Summary: test summary
Requires: {{ py2pkg("oslo.log") }}
%description
test description.
""")

    def test_help(self):
        self._run_renderspec(['-h'])

    def test_render(self):
        self._write_template('template.spec.j2')
        self._run_renderspec(['--input-template', 'template.spec.j2'])

    @mock.patch('renderspec._get_changelog_github', return_value=['l1', 'l2'])
    def test__get_changelog(self, mock_changelog_github):
        changes = sv._get_changelog('gh,openSUSE,obs-service-renderspec',
                                    '1.1.0', '2.2.0')
        self.assertEqual(changes, ['l1', 'l2'])

    def test__get_changelog_invalid_provider(self):
        with self.assertRaises(Exception):
            sv._get_changelog('foo,openSUSE,obs-service-renderspec',
                              '1.1.0', '2.2.0')

    def test__get_changes_string_no_changes(self):
        s = sv._get_changes_string([], 'foobar@example.com')
        self.assertEqual(s, None)
        s = sv._get_changes_string(None, 'foobar@example.com')
        self.assertEqual(s, None)

    @mock.patch('renderspec._get_changes_datetime',
                return_value='Mon Oct 17 05:22:25 UTC 2016')
    def test__get_changes_string(self, mock_utcnow):
        s = sv._get_changes_string(['l1', ['l2', 'l3'], 'l4'],
                                   'foobar@example.com')
        expected = """-------------------------------------------------------------------
Mon Oct 17 05:22:25 UTC 2016 - foobar@example.com

- l1
  - l2
  - l3
- l4

"""
        self.assertEqual(s, expected)

    def test__prepend_string_to_file(self):
        fn = os.path.join(self._tmpdir, 'prepentd_string_test1')
        with open(fn, 'w') as f:
            f.write('a line')
        sv._prepend_string_to_file('你好', fn)

    def test__extract_archive_to_tempdir_no_file(self):
        with self.assertRaises(Exception) as e_info:
            with sv._extract_archive_to_tempdir("foobar"):
                self.assertIn("foobar", str(e_info))

    def _write_pbr_json(self, destdir, git_version='6119f6f'):
        """write a pbr.json file into destdir"""
        f1 = os.path.join(destdir, 'pbr.json')
        with open(f1, 'w+') as f:
            f.write('{"git_version": "%s", "is_release": false}' % git_version)

    def test__find_pbr_json(self):
        tmpdir = tempfile.mkdtemp(prefix='obs-service-renderspec-test_')
        try:
            self._write_pbr_json(tmpdir)
            self.assertEqual(
                sv._find_pbr_json(tmpdir),
                os.path.join(tmpdir, 'pbr.json')
            )
        finally:
            shutil.rmtree(tmpdir)


if __name__ == '__main__':
    unittest.main()
