cd "$(dirname "$0")"
python -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/pyinstaller tshark.py -y
mkdir -p ../../bins_to_test/
cp -r dist/tshark ../../bins_to_test/
