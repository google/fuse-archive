#!/usr/bin/python3

# Copyright 2026 The Fuse-Archive Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os
import re
import subprocess
import sys


def run(cmd):
    subprocess.run(cmd, check=True)


def get_current_version():
    with open('fuse-archive.cc', 'r') as f:
        for line in f:
            match = re.search(r'#define PROGRAM_VERSION "(.*)"', line)
            if match:
                return match.group(1)
    raise ValueError('Could not find PROGRAM_VERSION in fuse-archive.cc')


def update_version(version, date=None):
    # Update fuse-archive.cc
    with open('fuse-archive.cc', 'r') as f:
        content = f.read()
    content = re.sub(r'#define PROGRAM_VERSION ".*"',
                     f'#define PROGRAM_VERSION "{version}"', content)
    with open('fuse-archive.cc', 'w') as f:
        f.write(content)

    # Update README.md
    with open('README.md', 'r') as f:
        content = f.read()
    content = re.sub(r'footer: fuse-archive .*',
                     f'footer: fuse-archive {version}', content)
    if date:
        content = re.sub(r'date: .*', f'date: {date}', content)
    with open('README.md', 'w') as f:
        f.write(content)

    # Regenerate man page
    run(['make', 'doc', 'QUIET=1'])


def main():
    current_version = get_current_version()
    major, minor = map(int, current_version.split('.'))

    if len(sys.argv) == 2:
        version = sys.argv[1]
    else:
        # Suggest next even version
        if minor % 2 != 0:
            version = f'{major}.{minor + 1}'
        else:
            version = f'{major}.{minor + 2}'

    match = re.match(r'^(\d+)\.(\d+)$', version)
    if not match:
        print(f'Invalid version format: {version}. Expected X.Y')
        sys.exit(1)

    stable_major = int(match.group(1))
    stable_minor = int(match.group(2))

    if stable_minor % 2 != 0:
        print(f'Version {version} is not an even (stable) version.')
        sys.exit(1)

    next_version = f'{stable_major}.{stable_minor + 1}'
    date = datetime.datetime.now().strftime('%B %Y')

    # Confirmation
    print(f'Current version: {current_version}')
    print(f'Release version: {version}')
    print(f'Next dev version: {next_version}')
    print(f'Release date:    {date}')

    confirm = input('Proceed with release? [y/N] ').lower()
    if confirm != 'y':
        print('Release cancelled.')
        sys.exit(0)

    # Check for clean git state
    res = subprocess.run(['git', 'status', '--porcelain'],
                         capture_output=True,
                         text=True)
    if res.stdout:
        print(
            'Git workspace is not clean. Please commit or stash your changes.')
        sys.exit(1)

    print(f'Releasing version {version}...')
    update_version(version, date)
    run(['git', 'add', 'fuse-archive.cc', 'README.md', 'fuse-archive.1'])
    run(['git', 'commit', '-m', f'Release version {version}'])
    run(['git', 'tag', '-a', f'v{version}', '-m', f'Version {version}'])

    print(f'Starting development version {next_version}...')
    update_version(next_version)
    run(['git', 'add', 'fuse-archive.cc', 'README.md', 'fuse-archive.1'])
    run(['git', 'commit', '-m', f'Start development version {next_version}'])

    print(f'\nSuccessfully released v{version} and bumped to {next_version}.')
    print('Don\'t forget to run: git push origin main --tags')


if __name__ == '__main__':
    main()
