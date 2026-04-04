#!/bin/bash
# Start the zkSNARK Authentication Web Application (Unix/Linux/Mac)

echo "============================================================"
echo "    zkSNARK Authentication System - Web Mode"
echo "============================================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python not found. Please install Python 3.8+"
    exit 1
fi

# Check if Node is available
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found. Please install Node.js 16+"
    exit 1
fi

# Check if zkSNARK artifacts exist
if [ ! -f "static/auth.wasm" ]; then
    echo "WARNING: zkSNARK artifacts not found in static/"
    echo "Please copy files manually or ensure setup is complete"
fi

echo "Starting Backend API Server..."
export PYTHONPATH="$(pwd)/backend"
python3 backend/api_server.py &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"
echo "Backend URL: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo ""

sleep 2

echo "Starting Frontend Dev Server..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

npm run dev &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"
echo "Frontend URL: http://localhost:5173"
echo ""

cd ..

echo "============================================================"
echo "Both servers are starting up..."
echo ""
echo "Open your browser to: http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both servers"
echo "============================================================"

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "Servers stopped."
    exit 0
}

# Trap Ctrl+C
trap cleanup INT

# Wait for user interrupt
wait

