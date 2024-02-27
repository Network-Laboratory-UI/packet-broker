#!/bin/bash

# Start a new Tmux session 
tmux new-session -d './build/packetBroker -l 0-2 -n 4'

# Now attach to the window
tmux attach-session