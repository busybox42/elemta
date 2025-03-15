#!/bin/sh
set -e
# Forward signals to the child process
trap 'kill -TERM $child' TERM INT
# Run the command
"$@" &
child=$!
# Wait for the child process to exit
wait $child
