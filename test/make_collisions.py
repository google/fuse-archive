#!/bin/python3

# Copyright 2024 The Fuse-Archive Authors.
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

import os
import os.path
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tmp = os.path.join(dir, 'collisions.zip~')

try:
  with ZipFile(tmp, 'w', compression=ZIP_DEFLATED, allowZip64=True) as z:
    z.writestr(
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (2)',
        b'This should be two',
    )
    z.writestr(
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file (4)',
        b'This should be four',
    )
    for i in range(100):
      warnings.filterwarnings(
          'ignore', message="Duplicate name: 'a/b/c/d/e/f/g/h/i/j/There are many versions of this file'")
      print('\rWriting collisions.zip... %3d %%' % i, end='', flush=True)
      for j in range(1000):
        z.writestr(
            'a/b/c/d/e/f/g/h/i/j/There are many versions of this file', b''
        )
    z.writestr(
        'a/b/c/d/e/f/g/h/i/j/There are many versions of this file', b'Last one'
    )

  print('\r\033[2KDone', flush=True)
  os.replace(tmp, os.path.join(dir, 'collisions.zip'))
except:
  os.remove(tmp)
