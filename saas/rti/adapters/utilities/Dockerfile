FROM python:3-slim as clone

RUN apt-get -y update
RUN apt-get -y install git

ARG GIT_REPO=https://github.com/cooling-singapore/saas-processor-template
RUN git clone $GIT_REPO /processor_repo

WORKDIR processor_repo
ARG COMMIT_ID=HEAD
RUN git checkout $COMMIT_ID

FROM python:3-slim as install
COPY --from=clone /processor_repo /processor_repo

COPY processor_scripts.py .
RUN python processor_scripts.py --repo-path /processor_repo

ARG PROCESSOR_NAME=dummy
WORKDIR /processor_repo/processor_$PROCESSOR_NAME

RUN mkdir /working_directory
ENTRYPOINT ["../venv/bin/python", "processor.py", "/working_directory"]
