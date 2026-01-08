#!/bin/bash
# Run the Media Organization Tool GUI

cd "$(dirname "$0")"
python3 gui.py &

# Wait a moment for the window to appear, then bring it to front
sleep 1
osascript -e 'tell application "System Events" to set frontmost of process "Python" to true' 2>/dev/null || \
osascript -e 'tell application "System Events" to set frontmost of process "python3" to true' 2>/dev/null || true
