#!/bin/bash

# the basic redis CLI command including host name parameter
CMD="redis-cli -h redis"

# write some string keys
$CMD SET simple_key_01 "Simple value"
$CMD SET simple_key_02/a "Simple value of a key containing a forward slash"

# keep service idle
while [ 1 ]
do
    $CMD ping
    sleep 60
done
