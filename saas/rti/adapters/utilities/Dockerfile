FROM python:3-slim
ARG PROC_ID
ARG PROC_CONFIG=default
ENV PROC_CONFIG=$PROC_CONFIG
ARG PROCESSOR_PATH=processor_test

LABEL proc_id=$PROC_ID

# FIXME: Remove sudo if possible. docker does not have sudo installed by default
RUN apt-get update && apt-get install sudo git -y

COPY processor_repo /processor_repo
WORKDIR /processor_repo/$PROCESSOR_PATH
# Make sure install and execute scripts is executable by user
RUN chmod +x *.sh
RUN ./install.sh $PROC_CONFIG

# Make sure directory exists
RUN mkdir /working_directory

ENTRYPOINT ./execute.sh $PROC_CONFIG /working_directory
