FROM python:2.7-alpine

MAINTAINER Marian Steinbach <marian@giantswarm.io>

ENV DEBIAN_FRONTEND noninteractive

ADD requirements.txt /
RUN pip install -r /requirements.txt
ADD . /app/

EXPOSE 5001
ENTRYPOINT ["python", "-u", "/app/runserver.py"]
