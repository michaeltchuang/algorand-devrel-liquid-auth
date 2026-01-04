#!/bin/bash

# Start the Falcon verification server

cd "$(dirname "$0")"

echo "Building Falcon verification server..."
go build -o falconserver main.go

if [ $? -eq 0 ]; then
    echo "Starting server on port 3002..."
    ./falconserver
else
    echo "Build failed!"
    exit 1
fi
