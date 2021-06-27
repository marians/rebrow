FROM python:3.9-alpine

MAINTAINER Jonathan Kelley <jonk@omg.lol>

ENV DEBIAN_FRONTEND noninteractive

#ADD requirements.txt /
#RUN pip install -r /requirements.txt
ADD . /app/

WORKDIR /app

RUN python3 setup.py install

EXPOSE 5001
ENTRYPOINT ["rebrow"]
