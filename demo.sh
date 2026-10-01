#!/bin/bash
# Controlled lab demo: create misconfiguration -> detect -> fix -> re-scan
cd "$(dirname "$0")"
echo "=== STEP 1: create a deliberately insecure script ==="
echo 'echo hello' > /tmp/lab_test.sh
chmod 777 /tmp/lab_test.sh
ls -l /tmp/lab_test.sh
echo; echo "=== STEP 2: scan (finding should appear) ==="
python3 main.py | grep -A3 "lab_test.sh"
echo; echo "=== STEP 3: fix it ==="
chmod 755 /tmp/lab_test.sh
ls -l /tmp/lab_test.sh
echo; echo "=== STEP 4: scan again (finding should be gone) ==="
python3 main.py | grep "lab_test.sh" || echo "No finding for lab_test.sh - fixed!"
rm -f /tmp/lab_test.sh
