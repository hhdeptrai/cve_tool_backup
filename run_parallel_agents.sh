#!/bin/bash
# Script để chạy song song nhiều tiến trình ai-agent

NUM_WORKERS=$1

if [ -z "$NUM_WORKERS" ]; then
    echo "Usage: ./run_parallel_agents.sh <number_of_workers>"
    exit 1
fi

echo "Starting $NUM_WORKERS parallel AI Agent workers..."

for i in $(seq 1 $NUM_WORKERS); do
    echo "Starting Worker $i..."
    # Chạy ngầm và redirect output để tránh spam terminal (hoặc có thể dùng tmux)
    ./venv/bin/python census ai-agent > "worker_${i}.log" 2>&1 &
done

echo "All workers started. You can check logs in worker_*.log"
echo "To stop them, run: pkill -f 'python census ai-agent'"
