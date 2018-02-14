#!/usr/bin/env python

import os
import sys

if sys.version_info.major == 2:
    os.system('pip install -r dev-requirements-2.7.txt')
elif sys.version_info.major == 3:
    os.system('pip install -r dev-requirements-3.x.txt')
else:
    raise Exception('Unsupported python version!')
