FROM python:3.8-slim

COPY ./requirements.txt /requirements.txt

RUN pip install flask
RUN pip install -r requirements.txt

COPY ./dependencies /processor/dependencies
COPY ./modules /processor/modules
COPY ./descriptor.json /processor/descriptor.json
COPY ./processor.py /processor/processor.py

COPY ./__tmp__/docker_wrapper.py /processor/docker_wrapper.py

ENTRYPOINT [ "python" ]

CMD [ "/processor/docker_wrapper.py" ]