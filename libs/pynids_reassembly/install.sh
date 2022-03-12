cd "$(dirname "$0")"
pip install virtualenv
virtualenv --python=/usr/bin/python2.7 venv
source venv/bin/activate
pip install -r requirements.txt
pyinstaller pynids_reassembly.py -y
mkdir -p ../../bins_to_test/
cp -r dist/pynids_reassembly ../../bins_to_test
deactivate
