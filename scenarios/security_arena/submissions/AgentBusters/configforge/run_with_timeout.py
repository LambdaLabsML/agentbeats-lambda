#!/usr/bin/env python3
"""
Wrapper script to run configforge scenario with extended timeout.
This is needed when using slow local vLLM inference.

Usage:
    python scenarios/security_arena/submissions/AgentBusters/configforge/run_with_timeout.py
    
Or with custom scenario:
    python scenarios/security_arena/submissions/AgentBusters/configforge/run_with_timeout.py path/to/scenario.toml
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))
sys.path.insert(0, os.path.join(project_root, "src"))

# Create a usercustomize.py in a temp directory to patch httpx in ALL subprocesses
import tempfile
import atexit
import shutil

# Create temp directory for usercustomize
temp_site_dir = tempfile.mkdtemp(prefix="httpx_patch_")

usercustomize_content = '''
import httpx

EXTENDED_TIMEOUT = httpx.Timeout(5000.0, connect=5000.0, read=5000.0, write=5000.0)

def _should_extend_timeout(timeout_val):
    if timeout_val is None:
        return True
    if isinstance(timeout_val, (int, float)):
        return timeout_val < 5000
    if isinstance(timeout_val, httpx.Timeout):
        read_timeout = timeout_val.read
        if read_timeout is not None and read_timeout < 5000:
            return True
    return False

_original_async_init = httpx.AsyncClient.__init__

def _patched_async_init(self, *args, **kwargs):
    if _should_extend_timeout(kwargs.get('timeout')):
        kwargs['timeout'] = EXTENDED_TIMEOUT
    _original_async_init(self, *args, **kwargs)

httpx.AsyncClient.__init__ = _patched_async_init

_original_sync_init = httpx.Client.__init__

def _patched_sync_init(self, *args, **kwargs):
    if _should_extend_timeout(kwargs.get('timeout')):
        kwargs['timeout'] = EXTENDED_TIMEOUT
    _original_sync_init(self, *args, **kwargs)

httpx.Client.__init__ = _patched_sync_init

print(f"[usercustomize] Patched httpx timeout to {EXTENDED_TIMEOUT}")
'''

# Write usercustomize.py
with open(os.path.join(temp_site_dir, "usercustomize.py"), "w") as f:
    f.write(usercustomize_content)

# Add to PYTHONPATH so subprocesses will load it
current_pythonpath = os.environ.get("PYTHONPATH", "")
if current_pythonpath:
    os.environ["PYTHONPATH"] = f"{temp_site_dir}:{current_pythonpath}"
else:
    os.environ["PYTHONPATH"] = temp_site_dir

# Enable user site packages
os.environ["ENABLE_USER_SITE"] = "1"

# Cleanup on exit
def cleanup():
    try:
        shutil.rmtree(temp_site_dir)
    except Exception:
        pass

atexit.register(cleanup)

print(f"[run_with_timeout] Created httpx patch in {temp_site_dir}")
print(f"[run_with_timeout] PYTHONPATH={os.environ['PYTHONPATH']}")

# Also patch current process
import httpx

EXTENDED_TIMEOUT = httpx.Timeout(3000.0, connect=3000.0, read=3000.0, write=3000.0)

def _should_extend_timeout(timeout_val):
    if timeout_val is None:
        return True
    if isinstance(timeout_val, (int, float)):
        return timeout_val < EXTENDED_TIMEOUT.read
    if isinstance(timeout_val, httpx.Timeout):
        read_timeout = timeout_val.read
        if read_timeout is not None and read_timeout < EXTENDED_TIMEOUT.read:
            return True
    return False

_original_async_init = httpx.AsyncClient.__init__

def _patched_async_init(self, *args, **kwargs):
    if _should_extend_timeout(kwargs.get('timeout')):
        kwargs['timeout'] = EXTENDED_TIMEOUT
    _original_async_init(self, *args, **kwargs)

httpx.AsyncClient.__init__ = _patched_async_init

_original_sync_init = httpx.Client.__init__

def _patched_sync_init(self, *args, **kwargs):
    if _should_extend_timeout(kwargs.get('timeout')):
        kwargs['timeout'] = EXTENDED_TIMEOUT
    _original_sync_init(self, *args, **kwargs)

httpx.Client.__init__ = _patched_sync_init

print(f"[run_with_timeout] Patched httpx timeout in main process")

# Default scenario path
DEFAULT_SCENARIO = "scenarios/security_arena/submissions/AgentBusters/configforge/scenario_configforge.toml"

if __name__ == "__main__":
    # Get scenario path from args or use default
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        scenario = sys.argv[1]
        args = sys.argv[2:]
    else:
        scenario = DEFAULT_SCENARIO
        args = sys.argv[1:]
    
    # Build new argv
    sys.argv = ["agentbeats-run", "--show-logs", scenario] + args
    
    # Run the scenario
    from agentbeats.run_scenario import main
    main()
