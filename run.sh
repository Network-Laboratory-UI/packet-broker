#!/bin/bash

# Start a new Tmux session 
tmux new-session -d './build/packetBroker -l 1 -n 4'

# Split the Tmux session into two horizontal panes
tmux split-pane -v './build/aggregator'

# Make all three panes the same size (currently, the first pane
# is 50% of the window, and the two new panes are 25% each).
tmux select-layout even-horizontal
# Now attach to the window
tmux attach-session