#!/bin/bash
# Run the Media Organization Tool GUI

cd "$(dirname "$0")"

# Function to check if Python has tkinter support
check_tkinter() {
    local python_cmd="$1"
    "$python_cmd" -c "import tkinter" 2>/dev/null
}

# Try to find a Python with tkinter support
PYTHON_CMD=""

# Try common Python locations
for python_path in \
    "$(which python3)" \
    "/opt/homebrew/bin/python3" \
    "/usr/local/bin/python3" \
    "/usr/bin/python3" \
    "$HOME/.pyenv/shims/python3" \
    "$(brew --prefix python@3.12)/bin/python3" \
    "$(brew --prefix python@3.11)/bin/python3" \
    "$(brew --prefix python@3.10)/bin/python3"
do
    if [ -n "$python_path" ] && [ -x "$python_path" ] && check_tkinter "$python_path"; then
        PYTHON_CMD="$python_path"
        break
    fi
done

# If no Python with tkinter found, try python3 from PATH
if [ -z "$PYTHON_CMD" ]; then
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
    fi
fi

# Check if we found a Python
if [ -z "$PYTHON_CMD" ]; then
    echo "Error: Could not find Python with tkinter support."
    echo "Please install Python with tkinter support, or install python-tk:"
    echo "  brew install python-tk"
    exit 1
fi

# Verify tkinter one more time
if ! check_tkinter "$PYTHON_CMD"; then
    echo "Error: Python at $PYTHON_CMD does not have tkinter support."
    echo "Please install Python with tkinter support:"
    echo "  brew install python-tk"
    exit 1
fi

echo "Using Python: $PYTHON_CMD"
"$PYTHON_CMD" gui.py &

# Wait a moment for the window to appear, then bring it to front
sleep 1
osascript -e 'tell application "System Events" to set frontmost of process "Python" to true' 2>/dev/null || \
osascript -e 'tell application "System Events" to set frontmost of process "python3" to true' 2>/dev/null || \
osascript -e 'tell application "System Events" to set frontmost of process "gui.py" to true' 2>/dev/null || true
