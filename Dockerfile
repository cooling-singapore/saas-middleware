FROM python:3.9-slim

ENV NODE_TYPE=full

RUN apt update && apt install -y git

COPY . /saas-mw
RUN pip install /saas-mw

# TODO: Find a better way to turn off strict mode when possible
ENTRYPOINT saas-cli --keystore /keystore --keystore-id $KEYSTORE_ID --password $PASSWORD service --datastore /datastore --rest-address $REST_ADDRESS --p2p-address $P2P_ADDRESS --boot-node $BOOT_NODE --use-defaults --bind-all-address --type $NODE_TYPE