#!/bin/bash

# the basic redis CLI command including host name parameter
CMD="redis-cli -h redis"

# Simple strings
$CMD SET string_01 "Simple value"
$CMD SET string_02/a "Simple value of a key containing a forward slash"
$CMD SET string_03 1
$CMD SET string_04 1.1

# Strings with expiry
$CMD SETEX string_05 10 "String expiring 10 seconds after creation"
$CMD SETEX string_06 100 "String expiring 100 seconds after creation"
$CMD SETEX string_07 1000 "String expiring 1000 seconds after creation"
$CMD SETEX string_08 10000 "String expiring 10000 seconds after creation"
$CMD SETEX string_09 100000 "String expiring 100000 seconds after creation"

# Lists
$CMD RPUSH list_01 "First list value"
$CMD RPUSH list_01 "Second list value"
$CMD RPUSH list_01 "Third list value"

# Sets
$CMD SADD set_01 "First set value"
$CMD SADD set_01 "Second set value"
$CMD SADD set_01 "Third set value"
$CMD SADD set_01 "Fourth set value"
$CMD SADD set_01 "Fifth set value"

# Hashes
$CMD HSET hash_01 field01 "Value of field_01"
$CMD HSET hash_01 field02 "Value of field_02"
$CMD HSET hash_01 field03 1234567
$CMD HSET hash_01 field04 5.6789
$CMD HSET hash_02 field01 "Value of field_01"
$CMD HSET hash_02 field02 "Value of field_02"
$CMD HSET hash_02 field03 1234567
$CMD HSET hash_02 field04 5.6789

# keep service idle
while [ 1 ]
do
    $CMD ping
    sleep 60
done
