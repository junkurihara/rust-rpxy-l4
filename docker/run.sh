#!/usr/bin/env sh
CONFIG_FILE=/etc/rpxy-l4.toml
LOG_DIR=/rpxy-l4/log
LOGGING=${LOG_TO_FILE:-false}

# debug level logging
if [ -z $LOG_LEVEL ]; then
  LOG_LEVEL=info
fi
echo "rpxy-l4: Logging with level ${LOG_LEVEL}"

if "${LOGGING}"; then
  echo "rpxy-l4: Start with writing log files"
  RUST_LOG=${LOG_LEVEL} /rpxy-l4/bin/rpxy-l4 --config ${CONFIG_FILE} --log-dir ${LOG_DIR}
else
  echo "rpxy-4: Start without writing log files"
  RUST_LOG=${LOG_LEVEL} /rpxy-l4/bin/rpxy-l4 --config ${CONFIG_FILE}
fi
