#!/bin/sh
cd "$(git rev-parse --show-toplevel)" || exit

safety check -r requirements.txt
