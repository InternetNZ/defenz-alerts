#!/bin/sh
cd "$(git rev-parse --show-toplevel)" || exit
[ -d venv ] && . venv/bin/activate

bandit  -r ./defenz_alerts