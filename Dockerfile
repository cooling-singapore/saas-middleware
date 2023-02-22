FROM python:3.9-slim

ENV NODE_TYPE=full
ENV STRICT=true

RUN apt update && apt install -y git

COPY . /saas-mw
RUN pip install /saas-mw

ENTRYPOINT exec saas-node --keystore /keystore --keystore-id $KEYSTORE_ID --password $PASSWORD \
--log-path /logs/node.log \
run --datastore /datastore --rest-address $REST_ADDRESS --p2p-address $P2P_ADDRESS --boot-node $BOOT_NODE \
--type $NODE_TYPE --bind-all-address \
$([ "$STRICT" = "false" ] && echo "--disable-strict-deployment")
