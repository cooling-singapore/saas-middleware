FROM python:3-slim

ENV NODE_TYPE=full

COPY . /saas-mw
RUN pip install /saas-mw

ENTRYPOINT saas-cli --keystore /keystore --keystore-id $KEYSTORE_ID --password $PASSWORD service --datastore /datastore --rest-address $REST_ADDRESS --p2p-address $P2P_ADDRESS --boot-node $BOOT_NODE --retain-job-history --bind-all-address --type $NODE_TYPE