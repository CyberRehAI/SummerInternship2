import sys
import subprocess
import os

def main():
    script_path = os.path.join(os.path.dirname(__file__), "Task3", "ArzensIntern_AbdulRehman_quality_validator.py")
    args = ["python", script_path] + sys.argv[1:]
    res = subprocess.run(args)
    sys.exit(res.returncode)

if __name__ == "__main__":
    main()
