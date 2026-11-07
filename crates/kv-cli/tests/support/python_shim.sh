#!/bin/bash
# A `python` stand-in for running kv-secrets' own tests/test_cli.py against the Rust binary:
# `python -m kv ...` and the tests' pty launcher `python -c "...runpy.run_module('kv')..."`
# run the Rust kv; everything else runs the reference interpreter with argv[0] kept, so
# `sys.executable` inside pytest is this shim.
#
#   mkdir shim && cp python_shim.sh shim/python && chmod +x shim/python
#   KV_PY_REF=/path/to/venv/bin/python KV_RUST_BIN=/path/to/target/release/kv \
#   PYTHONPATH=/path/to/venv/lib/python3.X/site-packages \
#     shim/python -m pytest tests/test_cli.py -q -p no:cacheprovider -rfp
#
# Both variables are required; the Python checkout is the current directory.
set -u
REAL="${KV_PY_REF:?set KV_PY_REF to the reference interpreter}"
RUST="${KV_RUST_BIN:?set KV_RUST_BIN to the Rust kv binary}"
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "kv" ]; then
  shift 2
  exec "$RUST" "$@"
fi
if [ "${1:-}" = "-c" ] && [[ "${2:-}" == *"run_module('kv'"* ]]; then
  shift 2
  exec "$REAL" -c "import fcntl,os,sys,termios
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
os.execv(sys.argv[1], ['kv'] + sys.argv[2:])" "$RUST" "$@"
fi
exec -a "$0" "$REAL" "$@"
