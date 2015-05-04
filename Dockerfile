FROM debian:jessie

MAINTAINER Marian Steinbach <marian@giantswarm.io>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -q

RUN apt-get install -qy --no-install-recommends python-pip build-essential python-dev

ADD requirements.txt /requirements.txt

RUN pip install -r requirements.txt

ADD runserver.py /runserver.py
ADD static /static
ADD templates /templates

ENTRYPOINT ["python", "-u", "runserver.py"]
