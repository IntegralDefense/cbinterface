#!/data/home/carbonblack/env3/bin/python3

import re
import sys

from cbinterface import main

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
