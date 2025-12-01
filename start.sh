#!/bin/bash
# Startup script for oXCookie Manager

# Change to deployment directory
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start the application
python3 app.py

