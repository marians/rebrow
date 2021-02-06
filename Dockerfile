FROM python:3.9-alpine

MAINTAINER Jonathan Kelley <jonk@omg.lol>

ENV DEBIAN_FRONTEND noninteractive

ADD requirements.txt /
RUN pip install -r /requirements.txt
ADD . /app/

EXPOSE 5001
ENTRYPOINT ["python", "-u", "/app/runserver.py"]
