import sys
import subprocess
import os

def main():
    script_path = os.path.join(os.path.dirname(__file__), "Task2", "ArzensIntern_AbdulRehman_log_parser.py")
    args = ["python", script_path] + sys.argv[1:]
    res = subprocess.run(args)
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
