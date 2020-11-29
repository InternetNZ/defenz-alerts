#!/bin/sh
cd "$(git rev-parse --show-toplevel)" || exit
[ -d venv ] && . venv/bin/activate

# exit when any command fails
set -e

# run pylint on app
pylint ./defenz_alerts
