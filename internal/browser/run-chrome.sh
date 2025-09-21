#!/bin/bash
# By using setsid, we launch Chrome in a new session, completely detached
# from the Go test runner's process tree. This breaks the inheritance of
# the "hostile" environment that was causing the browser to crash.
setsid /usr/bin/google-chrome-stable "$@"

