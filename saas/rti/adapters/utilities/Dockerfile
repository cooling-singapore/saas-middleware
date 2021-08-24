FROM python:3-slim as clone
ARG PROC_ID
ARG GIT_REPO=https://github.com/cooling-singapore/saas-processor-template
ARG COMMIT_ID=HEAD

LABEL proc_id=$PROC_ID

RUN apt-get update && apt-get install -y git
RUN git clone $GIT_REPO /processor_repo

WORKDIR processor_repo
RUN git checkout $COMMIT_ID

FROM python:3-slim as install
ARG PROC_ID
ARG PROCESSOR_PATH=processor_test

LABEL proc_id=$PROC_ID

COPY --from=clone /processor_repo /processor_repo

WORKDIR /processor_repo/$PROCESSOR_PATH
RUN echo "$PWD"
RUN ./install.sh default

RUN mkdir /working_directory
ENTRYPOINT ["./execute.sh", "default", "/working_directory"]
