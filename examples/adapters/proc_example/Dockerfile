FROM ubuntu:22.04
RUN apt update -y
RUN apt upgrade -y
RUN apt install -y tzdata
RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt update -y
RUN apt install -y python3.10 python3.10-distutils python3-pip git

RUN git clone https://github.com/cooling-singapore/saas-middleware /saas-middleware
WORKDIR /saas-middleware
RUN git checkout 64482cd1c1f24d55b0c17e606782f49a5fc51d7d

WORKDIR /processor
COPY . .
RUN python3.10 -m pip install -r ./requirements.txt
RUN python3.10 -m pip install /saas-middleware

EXPOSE 5000

ENTRYPOINT ["saas-cli", "run", "--job-path", "/job", "--proc-path", "/processor", "--rest-address", "0.0.0.0:5000"]
