FROM debian:jessie

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update -q

RUN apt-get install -qy --no-install-recommends redis-tools

ADD fill.sh /fill.sh
RUN chmod u+x /fill.sh

ENTRYPOINT ["/fill.sh"]
