#!/bin/bash
# Simple test script for IronJail debugging

echo "Starting test script execution..."
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "Environment variables:"
env | head -10
echo "Process ID: $$"
echo "Available commands:"
which ls cat echo date
echo "Testing file operations..."
echo "Hello from test script" > /tmp/test-file.txt
cat /tmp/test-file.txt
echo "Script completed successfully."