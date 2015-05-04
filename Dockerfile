FROM debian:jessie

MAINTAINER Marian Steinbach <marian@giantswarm.io>

ENV DEBIAN_FRONTEND noninteractive

COPY requirements.txt /requirements.txt

RUN set -x \
	&& apt-get update -q \
	&& apt-get install -qy --no-install-recommends \
	python-pip build-essential python-dev \
	&& pip install -r requirements.txt \
	&& apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false -o APT::AutoRemove::SuggestsImportant=false build-essential python-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY runserver.py /runserver.py
ADD static /static
ADD templates /templates

ENTRYPOINT ["python", "-u", "runserver.py"]
