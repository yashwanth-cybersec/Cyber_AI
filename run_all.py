# run_all.py  — Start monitoring engine + dashboard together

import threading
import time
import sys
import os
import json

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_config():
    """Load configuration from config.json"""
    config_file = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Set environment variables
                for key, value in config.items():
                    if value:
                        os.environ[key.upper()] = str(value)
                print(f"  [Config] Loaded from {config_file}")
                return config
        except Exception as e:
            print(f"  [Config] Error loading: {e}")
    return {}


def start_dashboard(state):
    """Start the Flask dashboard with error handling"""
    try:
        print("  [Dashboard] Importing dashboard.app...")
        from dashboard.app import run_dashboard
        print("  [Dashboard] Import successful, starting server...")
        run_dashboard(state, host="0.0.0.0", port=5000)
    except ImportError as e:
        print(f"  [Dashboard] Import Error: {e}")
        print(f"  [Dashboard] Make sure flask is installed: pip install flask flask-cors")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"  [Dashboard] Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    print("=" * 58)
    print("  CYBER AI — FULL SYSTEM STARTUP")
    print("  Starting monitoring engine + live dashboard...")
    print("=" * 58)

    # Load configuration
    config = load_config()

    try:
        import realtime_engine as engine
        print("  [Engine] realtime_engine imported successfully")

        # Start Flask dashboard in background thread
        print("  [Dashboard] Starting dashboard thread...")
        t = threading.Thread(
            target=start_dashboard,
            args=(engine.shared_state,),
            daemon=True
        )
        t.start()
        
        # Wait for dashboard to initialize
        time.sleep(2)
        
        print(f"\n  Dashboard → http://127.0.0.1:5000")
        print(f"  Open in browser now.\n")

        # Run monitoring loop (blocking)
        print("  [Engine] Starting monitoring loop...")
        engine.run()

    except ImportError as e:
        print(f"\n  [Import error] {e}")
        print(f"  Run from inside the cyber_ai folder.")
        print(f"  Make sure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  System stopped.")
    except Exception as e:
        print(f"\n  [Unexpected error] {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()