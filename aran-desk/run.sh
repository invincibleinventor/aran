#!/bin/sh
cd "$(dirname "$0")"
(sleep 1.5 && open "http://localhost:8000") &
exec uv run -q python main.py
