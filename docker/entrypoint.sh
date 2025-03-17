#!/usr/bin/env sh
LOG_DIR=/rpxy-l4/log
LOG_FILE=${LOG_DIR}/rpxy-l4.log
LOG_SIZE=10M
LOG_NUM=10

LOGGING=${LOG_TO_FILE:-false}
USER=${HOST_USER:-rpxy}
USER_ID=${HOST_UID:-900}
GROUP_ID=${HOST_GID:-900}

CONFIG_FILE=/etc/rpxy-l4.toml
CONFIG_DIR=/rpxy-l4/config
CONFIG_FILE_IN_DIR=${CONFIG_FILENAME:-config.toml}

#######################################
# Setup logrotate
function setup_logrotate () {
  if [ $LOGROTATE_NUM ]; then
    LOG_NUM=${LOGROTATE_NUM}
  fi
  if [ $LOGROTATE_SIZE ]; then
    LOG_SIZE=${LOGROTATE_SIZE}
  fi

  cat > /etc/logrotate.conf << EOF
# see "man logrotate" for details
# rotate log files weekly
weekly
# use the adm group by default, since this is the owning group
# of /var/log/syslog.
# su root adm
# keep 4 weeks worth of backlogs
rotate 4
# create new (empty) log files after rotating old ones
create
# use date as a suffix of the rotated file
#dateext
# uncomment this if you want your log files compressed
#compress
# packages drop log rotation information into this directory
include /etc/logrotate.d
# system-specific logs may be also be configured here.
EOF

  cat > /etc/logrotate.d/rpxy-l4.conf << EOF
${LOG_FILE} {
    dateext
    daily
    missingok
    rotate ${LOG_NUM}
    notifempty
    compress
    delaycompress
    dateformat -%Y-%m-%d-%s
    size ${LOG_SIZE}
    copytruncate
    su ${USER} ${USER}
}
EOF
}

#######################################
function setup_alpine () {
  id ${USER} > /dev/null
  # Check the existence of the user, if not exist, create it.
  if [ $? -eq 1 ]; then
    echo "rpxy-l4: Create user ${USER} with ${USER_ID}:${GROUP_ID}"
    addgroup -g ${GROUP_ID} ${USER}
    adduser -H -D -u ${USER_ID} -G ${USER} ${USER}
  fi

  # for crontab when logging
  if "${LOGGING}"; then
    # Set up logrotate
    setup_logrotate

    # Setup cron
    cp -f /etc/periodic/daily/logrotate /etc/periodic/15min
    crond -b -l 8
  fi
}

#######################################

if [ $(whoami) != "root" -o $(id -u) -ne 0 -a $(id -g) -ne 0 ]; then
  echo "Do not execute 'docker run' or 'docker-compose up' with a specific user through '-u'."
  echo "If you want to run 'rpxy-l4' with a specific user, use HOST_USER, HOST_UID and HOST_GID environment variables."
  exit 1
fi

# Add user CAs to OS trusted CA store (does not affect webpki)
update-ca-certificates

# Check the given user and its uid:gid
if [ $(id -u ${USER}) -ne ${USER_ID} -a $(id -g ${USER}) -ne ${GROUP_ID} ]; then
  echo "${USER} exists or was previously created. However, its uid and gid are inconsistent. Please recreate your container."
  exit 1
fi

# Change permission according to the given user
# except for the config dir that possibly get mounted with read-only
find /rpxy-l4 -path ${CONFIG_DIR} -prune -o -exec chown ${USER_ID}:${USER_ID} {} +

# Check the config file existence
if [[ ! -f ${CONFIG_FILE} ]]; then
  if [[ ! -f ${CONFIG_DIR}/${CONFIG_FILE_IN_DIR} ]]; then
    echo "No config file is given. Mount a config dir or file."
    exit 1
  fi
  echo "rpxy-l4: config file: ${CONFIG_DIR}/${CONFIG_FILE_IN_DIR}"
  ln -s ${CONFIG_DIR}/${CONFIG_FILE_IN_DIR} ${CONFIG_FILE}
else
  echo "rpxy-l4: config file: ${CONFIG_FILE}"
fi

# Run rpxy-l4
cd /rpxy-l4
echo "rpxy-l4: Start with user: ${USER} (${USER_ID}:${GROUP_ID})"
if "${LOGGING}"; then
  echo "rpxy-l4: Start with writing log file"
  su-exec ${USER} sh -c "/rpxy-l4/run.sh 2>&1 | tee ${LOG_FILE}"
else
  echo "rpxy-l4: Start without writing log file"
  su-exec ${USER} sh -c "/rpxy-l4/run.sh 2>&1"
fi
