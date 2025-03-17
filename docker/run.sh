#!/usr/bin/env sh
CONFIG_FILE=/etc/rpxy-l4.toml

# debug level logging
if [ -z $LOG_LEVEL ]; then
  LOG_LEVEL=info
fi
echo "rpxy-l4: Logging with level ${LOG_LEVEL}"

RUST_LOG=${LOG_LEVEL} /rpxy-l4/bin/rpxy-l4 --config ${CONFIG_FILE}
