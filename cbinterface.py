#!/usr/bin/env python3

"""
This file is only included in the cbinterface repo 
for the purpose of convenient testing
"""

import re
import sys

from cbinterface import main

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
