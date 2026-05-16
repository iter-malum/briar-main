#!/bin/bash
set -e

DISPLAY_NUM=":1"
VNC_PORT=5900
NOVNC_PORT=6080

echo "[briar-auth] Starting Xvfb on display $DISPLAY_NUM..."
Xvfb $DISPLAY_NUM -screen 0 1280x900x24 -ac &
sleep 2

echo "[briar-auth] Starting x11vnc..."
x11vnc -display $DISPLAY_NUM -rfbport $VNC_PORT -forever -nopw -quiet -xkb 2>/dev/null &
sleep 1

echo "[briar-auth] Starting noVNC on port $NOVNC_PORT..."
websockify --web=/opt/novnc $NOVNC_PORT localhost:$VNC_PORT &
sleep 1

export DISPLAY=$DISPLAY_NUM
echo "[briar-auth] Starting auth service on port 8000..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info
