Has Python3 version available as pull request.
But that didn't work and resulted in a segfault!

use `virtualenv --python=/usr/bin/python2.7 venv` to create the virtual environment (can't use integrated python 3 method)
don't forget to source the virtual environment `source venv/bin/activate`
install lib with `pip install git+https://github.com/MITRECND/pynids.git`
