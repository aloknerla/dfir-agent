#!/bin/sh
set -eu

# The binary is compiled against the libraries bundled beside it, not against
# whatever the console base image happens to carry, so the loader is pointed at
# the version-stamped prefix before the tool starts.
export LD_LIBRARY_PATH=/opt/bulk_extractor-2.1.1/lib
# The caller already supplies the exact argv it audited. Forward it verbatim:
# adding, removing, or reordering an argument here would silently execute a
# different scan than the one that was recorded.
exec /opt/bulk_extractor-2.1.1/bin/bulk_extractor "$@"
