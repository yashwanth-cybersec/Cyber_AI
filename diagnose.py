# diagnose.py
import sys
import os

print("=" * 50)
print("CYBER AI DIAGNOSTIC")
print("=" * 50)

# Check current directory
print(f"\nCurrent directory: {os.getcwd()}")

# Check if required files exist
required_files = [
    "realtime_engine.py",
    "dashboard/app.py",
    "utils/self_threat_intel.py",
    "utils/__init__.py"
]

print("\nChecking required files:")
for f in required_files:
    if os.path.exists(f):
        print(f"  ✓ {f}")
    else:
        print(f"  ✗ {f} - MISSING!")

# Check imports
print("\nChecking imports:")
modules = [
    'flask', 'flask_cors', 'colorama', 'psutil', 
    'sklearn', 'networkx', 'numpy', 'cryptography',
    'socket', 'ipaddress', 'json', 'time'
]

for m in modules:
    try:
        __import__(m)
        print(f"  ✓ {m}")
    except ImportError as e:
        print(f"  ✗ {m}: {e}")

# Try to import CyberAI modules
print("\nChecking CyberAI modules:")
cyber_modules = [
    'utils.self_threat_intel',
    'dashboard.app',
    'realtime_engine'
]

for m in cyber_modules:
    try:
        __import__(m)
        print(f"  ✓ {m}")
    except Exception as e:
        print(f"  ✗ {m}: {e}")

print("\n" + "=" * 50)