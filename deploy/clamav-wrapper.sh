#!/bin/sh
set -eu

export LD_LIBRARY_PATH=/opt/clamav-1.5.3/lib
exec /opt/clamav-1.5.3/bin/clamscan "$@"
