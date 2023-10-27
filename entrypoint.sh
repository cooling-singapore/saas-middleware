#!/bin/bash

# Environment Variables with Defaults
PASSWORD="${PASSWORD:-default_password}"
KEYSTORE="${KEYSTORE:-/keystore}"
DATASTORE="${DATASTORE:-datastore}"
LOG_PATH="${LOG_PATH:-/log}"
REST_ADDRESS="${REST_ADDRESS:-0.0.0.0:5000}"
P2P_ADDRESS="${P2P_ADDRESS:-0.0.0.0:5001}"
BOOT_NODE="${BOOT_NODE:-boot_node:5001}"
NODE_TYPE="${NODE_TYPE:-full}"
STRICT="${STRICT:-true}"

# NODE_ID is a required environment variable, script exits if not set
if [ -z "$NODE_ID" ]; then
  echo "Error: NODE_ID is not set."
  exit 1
fi

# Clear keystore folder
rm -rf /keystore/*

# Create identity
saas-cli --keystore $KEYSTORE --password $PASSWORD identity create --name 'foo bar' --email 'foo.bar@email.com'

# Pause for 5 seconds to ensure keystore files are created
sleep 5

# List and count keystore files
files=($(ls $KEYSTORE | sort))
echo "Total files in $KEYSTORE: ${#files[@]}"
echo "Files: ${files[*]}"

# Determine file to use based on NODE_ID
if [ "$NODE_ID" == "1" ] && [ ${#files[@]} -ge 1 ]; then
    file_to_use="${files[0]%".json"}"
elif [ "$NODE_ID" == "2" ] && [ ${#files[@]} -ge 2 ]; then
    file_to_use="${files[1]%".json"}"
else
    echo "Error: Invalid NODE_ID or insufficient keystore files."
    exit 1
fi

echo "file_to_use: $file_to_use"

# Run saas-node with determined parameters
saas-node --keystore $KEYSTORE --keystore-id $file_to_use --password $PASSWORD --log-path $LOG_PATH run \
  --datastore $DATASTORE --rest-address $REST_ADDRESS --p2p-address $P2P_ADDRESS --boot-node $BOOT_NODE \
  --type $NODE_TYPE --bind-all-address $([ "$STRICT" = "false" ] && echo "--disable-strict-deployment")

# saas-node --keystore $KEYSTORE --keystore-id $file_to_use --password $PASSWORD --log-path $LOG_PATH run --datastore /datastore --rest-address $REST_ADDRESS --p2p-address $P2P_ADDRESS --boot-node $BOOT_NODE --type $NODE_TYPE --bind-all-address $([ "$STRICT" = "false" ] && echo "--disable-strict-deployment")

# saas-relay --datastore $datastore --keystore /keystore --keystore-id $filename_without_extension --password $password  --log-path $log_path --log-level INFO service --userstore $userstore --bdp_directory $bdp_path --secret_key $secret --server_address '0.0.0.0:5005' --node_address 'boot_node:5001' --app_domains 'test123'

## Externalise datastore