cd "$(dirname "$0")"
python -m venv venv
venv/bin/pip install -r requirements.txt
for f in *.py; do venv/bin/python "$f"; done
