# encoding: utf8

from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, Markup, Response, json
import redis
from redis.sentinel import Sentinel

import time
from datetime import datetime, timedelta
import os
import base64
import jwt
import hashlib
from sys import version_info
from ast import literal_eval
import uuid
import sys

import logging
from simple_settings import settings
import traceback

logger = logging.getLogger("rebrow_logger")

app = Flask(__name__)

# key for cookie safety. Shal be overridden using ENV var SECRET_KEY
app.secret_key = os.getenv("SECRET_KEY", "lasfuoi3ro8w7gfow3bwiubdwoeg7p23r8g23rg")

# Description of info keys
# TODO: to be continued.
serverinfo_meta = {
    "aof_current_rewrite_time_sec": "Duration of the on-going <abbr title='Append-Only File'>AOF</abbr> rewrite operation if any",
    "aof_enabled": "Flag indicating <abbr title='Append-Only File'>AOF</abbr> logging is activated",
    "aof_last_bgrewrite_status": "Status of the last <abbr title='Append-Only File'>AOF</abbr> rewrite operation",
    "aof_last_rewrite_time_sec": "Duration of the last <abbr title='Append-Only File'>AOF</abbr> rewrite operation in seconds",
    "aof_last_write_status": "Status of last <abbr title='Append-Only File'>AOF</abbr> write operation",
    "aof_rewrite_in_progress": "Flag indicating a <abbr title='Append-Only File'>AOF</abbr> rewrite operation is on-going",
    "aof_rewrite_scheduled": "Flag indicating an <abbr title='Append-Only File'>AOF</abbr> rewrite operation will be scheduled once the on-going RDB save is complete",
    "arch_bits": "Architecture (32 or 64 bits)",
    "blocked_clients": "Number of clients pending on a blocking call (BLPOP, BRPOP, BRPOPLPUSH)",
    "client_biggest_input_buf": "biggest input buffer among current client connections",
    "client_longest_output_list": None,
    "cmdstat_client": "Statistics for the client command",
    "cmdstat_config": "Statistics for the config command",
    "cmdstat_dbsize": "Statistics for the dbsize command",
    "cmdstat_del": "Statistics for the del command",
    "cmdstat_dump": "Statistics for the dump command",
    "cmdstat_expire": "Statistics for the expire command",
    "cmdstat_flushall": "Statistics for the flushall command",
    "cmdstat_get": "Statistics for the get command",
    "cmdstat_hgetall": "Statistics for the hgetall command",
    "cmdstat_hkeys": "Statistics for the hkeys command",
    "cmdstat_hmset": "Statistics for the hmset command",
    "cmdstat_info": "Statistics for the info command",
    "cmdstat_keys": "Statistics for the keys command",
    "cmdstat_llen": "Statistics for the llen command",
    "cmdstat_ping": "Statistics for the ping command",
    "cmdstat_psubscribe": "Statistics for the psubscribe command",
    "cmdstat_pttl": "Statistics for the pttl command",
    "cmdstat_sadd": "Statistics for the sadd command",
    "cmdstat_scan": "Statistics for the scan command",
    "cmdstat_select": "Statistics for the select command",
    "cmdstat_set": "Statistics for the set command",
    "cmdstat_smembers": "Statistics for the smembers command",
    "cmdstat_sscan": "Statistics for the sscan command",
    "cmdstat_ttl": "Statistics for the ttl command",
    "cmdstat_type": "Statistics for the type command",
    "cmdstat_zadd": "Statistics for the zadd command",
    "cmdstat_zcard": "Statistics for the zcard command",
    "cmdstat_zrange": "Statistics for the zrange command",
    "cmdstat_zremrangebyrank": "Statistics for the zremrangebyrank command",
    "cmdstat_zrevrange": "Statistics for the zrevrange command",
    "cmdstat_zscan": "Statistics for the zscan command",
    "config_file": None,
    "connected_clients": None,
    "connected_slaves": None,
    "db0": None,
    "evicted_keys": None,
    "expired_keys": None,
    "gcc_version": None,
    "hz": None,
    "instantaneous_ops_per_sec": None,
    "keyspace_hits": None,
    "keyspace_misses": None,
    "latest_fork_usec": None,
    "loading": None,
    "lru_clock": None,
    "master_repl_offset": None,
    "mem_allocator": None,
    "mem_fragmentation_ratio": None,
    "multiplexing_api": None,
    "os": None,
    "process_id": None,
    "pubsub_channels": None,
    "pubsub_patterns": None,
    "rdb_bgsave_in_progress": None,
    "rdb_changes_since_last_save": None,
    "rdb_current_bgsave_time_sec": None,
    "rdb_last_bgsave_status": None,
    "rdb_last_bgsave_time_sec": None,
    "rdb_last_save_time": None,
    "redis_build_id": None,
    "redis_git_dirty": None,
    "redis_git_sha1": None,
    "redis_mode": None,
    "redis_version": None,
    "rejected_connections": None,
    "repl_backlog_active": None,
    "repl_backlog_first_byte_offset": None,
    "repl_backlog_histlen": None,
    "repl_backlog_size": None,
    "role": None,
    "run_id": None,
    "sync_full": None,
    "sync_partial_err": None,
    "sync_partial_ok": None,
    "tcp_port": None,
    "total_commands_processed": None,
    "total_connections_received": None,
    "uptime_in_days": None,
    "uptime_in_seconds": None,
    "used_cpu_sys": None,
    "used_cpu_sys_children": None,
    "used_cpu_user": None,
    "used_cpu_user_children": None,
    "used_memory": None,
    "used_memory_human": None,
    "used_memory_lua": None,
    "used_memory_peak": None,
    "used_memory_peak_human": None,
    "used_memory_rss": None
}


# Added token, client_id and salt to replace password parameter and determining
# client protocol
def get_client_details():
    """
    Gets the first X-Forwarded-For address and sets as the IP address.
    Gets the client_id by simply using a md5 hash of the client IP address
    and user agent.
    Determines whether the request was proxied.
    Determines the client protocol.
    :return: client_id, protocol, proxied
    :rtype: str, str, boolean, str
    """
    proxied = False
    if request.headers.getlist('X-Forwarded-For'):
        client_ip = str(request.headers.getlist('X-Forwarded-For')[0])
        logger.info('rebrow access :: client ip set from X-Forwarded-For[0] to %s' % (str(client_ip)))
        proxied = True
    else:
        client_ip = str(request.remote_addr)
        logger.info('rebrow access :: client ip set from remote_addr to %s, no X-Forwarded-For header was found' % (
            str(client_ip)))
    client_user_agent = request.headers.get('User-Agent')
    logger.info('rebrow access :: %s client_user_agent set to %s' % (str(client_ip), str(client_user_agent)))
    client_id = '%s_%s' % (client_ip, client_user_agent)
    if sys.version_info[0] == 2:
        client_id = hashlib.md5(client_id).hexdigest()
    else:
        client_id = hashlib.md5(client_id.encode('utf-8')).hexdigest()
    logger.info('rebrow access :: %s has client_id %s' % (str(client_ip), str(client_id)))

    if request.headers.getlist('X-Forwarded-Proto'):
        protocol_list = request.headers.getlist('X-Forwarded-Proto')
        protocol = str(protocol_list[0])
        logger.info(
            'rebrow access :: protocol for %s was set from X-Forwarded-Proto to %s' % (client_ip, str(protocol)))
    else:
        protocol = 'unknown'
        logger.info(
            'rebrow access :: protocol for %s was not set from X-Forwarded-Proto to %s' % (client_ip, str(protocol)))

    if not proxied:
        logger.info(
            'rebrow access :: Skyline is not set up correctly, the expected X-Forwarded-For header was not found')

    return client_id, protocol, proxied


def decode_token(client_id):
    """
    Use the app.secret, client_id and salt to decode the token JWT encoded
    payload and determine the Redis password.
    :param client_id: the client_id string
    :type client_id: str
    return token, decoded_redis_password, fail_msg, trace
    :return: token, decoded_redis_password, fail_msg, trace
    :rtype: str, str, str, str
    """
    fail_msg = False
    trace = False
    token = False
    logger.info('decode_token for client_id - %s' % str(client_id))

    if not request.args.getlist('client_token'):
        fail_msg = 'No token url parameter was passed, please log into Redis again through rebrow'
    else:
        token = request.args.get('client_token', type=str)
        logger.info('token found in request.args - %s' % str(token))

    if not token:
        client_id, protocol, proxied = get_client_details()
        fail_msg = 'No token url parameter was passed, please log into Redis again through rebrow'
        trace = 'False'

    client_token_data = False
    if token:
        try:
            if settings.REDIS_PASSWORD:
                redis_conn = redis.StrictRedis(password=settings.REDIS_PASSWORD,
                                               host=settings.REDIS_HOST,
                                               port=settings.REDIS_PORT)
            else:
                redis_conn = redis.StrictRedis(host=settings.REDIS_HOST,
                                               port=settings.REDIS_PORT)
            key = 'rebrow.token.%s' % token
            client_token_data = redis_conn.get(key)
        except:
            trace = traceback.format_exc()
            fail_msg = 'Failed to get client_token_data from Redis key - %s' % key
            client_token_data = False
            token = False

    client_id_match = False
    if client_token_data is not None:
        logger.info('client_token_data retrieved from Redis - %s' % str(client_token_data))
        try:
            client_data = literal_eval(client_token_data)
            logger.info('client_token_data - %s' % str(client_token_data))
            client_data_client_id = str(client_data[0])
            logger.info('client_data_client_id - %s' % str(client_data_client_id))
        except:
            trace = traceback.format_exc()
            logger.error('%s' % trace)
            err_msg = 'error :: failed to get client data from Redis key'
            logger.error('%s' % err_msg)
            fail_msg = 'Invalid token. Please log into Redis through rebrow again.'
            client_data_client_id = False

        if client_data_client_id != client_id:
            logger.error(
                'rebrow access :: error :: the client_id does not match the client_id of the token - %s - %s' %
                (str(client_data_client_id), str(client_id)))
            try:
                if settings.REDIS_PASSWORD:
                    redis_conn = redis.StrictRedis(password=settings.REDIS_PASSWORD)
                else:
                    redis_conn = redis.StrictRedis()

                key = 'rebrow.token.%s' % token
                redis_conn.delete(key)
                logger.info(
                    'due to possible attempt at unauthorised use of the token, deleted the Redis key - %s' % str(key))
            except:
                pass
            fail_msg = 'The request data did not match the token data, due to possible attempt at unauthorised use of the token it has been deleted.'
            trace = 'this was a dodgy request'
            token = False
        else:
            client_id_match = True
    else:
        fail_msg = 'Invalid token, there was no data found associated with the token, it has probably expired.  Please log into Redis again through rebrow'
        trace = client_token_data
        token = False

    client_data_salt = False
    client_data_jwt_payload = False
    if client_id_match:
        client_data_salt = str(client_data[1])
        client_data_jwt_payload = str(client_data[2])

    decoded_redis_password = False
    if client_data_salt and client_data_jwt_payload:
        jwt_secret = '%s.%s.%s' % (app.secret_key, client_id, client_data_salt)
        jwt_decoded_dict = jwt.decode(client_data_jwt_payload, jwt_secret, algorithms=['HS256'])
        jwt_decoded_redis_password = str(jwt_decoded_dict['auth'])
        decoded_redis_password = jwt_decoded_redis_password

    return token, decoded_redis_password, fail_msg, trace


def get_redis(host, port, db, sentinel):
    client_id, protocol, proxied = get_client_details()
    token, redis_password, fail_msg, trace = decode_token(client_id)
    if not token:
        abort(401)

    if sentinel == 'on':
        _sentinel = Sentinel([(host, port)], socket_timeout=0.1)
        return sentinel.master_for(
            'mymaster', db=db, password=redis_password, socket_timeout=0.1)
    else:
        if redis_password == "":
            return redis.StrictRedis(host=host, port=port, db=db)

        return redis.StrictRedis(host=host, port=port, db=db, password=redis_password)


@app.route("/", methods=['GET', 'POST'])
def login():
    """
    Start page
    """
    if request.method == 'POST':
        # TODO: test connection, handle failures
        host = request.form["host"]
        port = int(request.form["port"])
        db = int(request.form["db"])
        sentinel = request.form.get("sentinel")
        password = str(request.form['password'])
        token_valid_for = int(request.form['token_valid_for'])
        if token_valid_for > 3600:
            token_valid_for = 3600
        if token_valid_for < 30:
            token_valid_for = 30

        client_id, protocol, proxied = get_client_details()

        salt = salt = str(uuid.uuid4())

        # Use pyjwt - JSON Web Token implementation to encode the password and
        # pass a token in the URL password parameter, the password in the POST
        # data should be encrypted via the reverse proxy SSL endpoint
        # encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
        # jwt.decode(encoded, 'secret', algorithms=['HS256'])
        # {'some': 'payload'}
        try:
            jwt_secret = '%s.%s.%s' % (app.secret_key, client_id, salt)
            jwt_encoded_payload = jwt.encode({'auth': str(password)}, jwt_secret, algorithm='HS256')
        except:
            message = 'Failed to create set jwt_encoded_payload for %s' % client_id
            trace = traceback.format_exc()
            logging.log(message, trace)
            abort(500)

        # HERE WE WANT TO PUT THIS INTO REDIS with a TTL key and give the key
        # a salt and have the client use that as their token
        client_token = str(uuid.uuid4())
        logger.info('rebrow access :: generated client_token %s for client_id %s' % (client_token, client_id))
        try:
            if settings.REDIS_PASSWORD:
                redis_conn = redis.StrictRedis(password=settings.REDIS_PASSWORD,
                                               host=settings.REDIS_HOST,
                                               port=settings.REDIS_PORT)
            else:
                redis_conn = redis.StrictRedis(host=settings.REDIS_HOST,
                                               port=settings.REDIS_PORT)
            key = 'rebrow.token.%s' % client_token
            value = '[\'%s\',\'%s\',\'%s\']' % (client_id, salt, jwt_encoded_payload)
            redis_conn.setex(key, token_valid_for, value)
            logger.info('rebrow access :: set Redis key - %s' % (key))
        except:
            message = 'Failed to set Redis key - %s' % key
            trace = traceback.format_exc()
            logging.log(message, trace)
            abort(500)

        if sentinel is None:
            sentinel = 'off'

        url = url_for("server_db", host=host, port=port, db=db, client_token=client_token, sentinel=sentinel)
        return redirect(url)
    else:
        s = time.time()
        return render_template('login.html',
                               duration=time.time() - s)


@app.route("/<host>:<int:port>/<int:db>/")
def server_db(host, port, db):
    """
    List all databases and show info on server
    """
    s = time.time()

    client_token = request.args.get('client_token', default='off', type=str)
    sentinel = request.args.get('sentinel', default='off', type=str)

    r = get_redis(host, port, db, sentinel)

    info = r.info("all")
    dbsize = r.dbsize()
    return render_template('server.html',
                           host=host,
                           port=port,
                           client_token=client_token,
                           db=db,
                           info=info,
                           dbsize=dbsize,
                           serverinfo_meta=serverinfo_meta,
                           duration=time.time() - s)


@app.route("/<host>:<int:port>/<int:db>/keys/", methods=['GET', 'POST'])
def keys(host, port, db):
    """
    List keys for one database
    """
    s = time.time()

    client_token = request.args.get('client_token', default='off', type=str)
    sentinel = request.args.get('sentinel', default='off', type=str)

    r = get_redis(host, port, db, sentinel)

    if request.method == "POST":
        action = request.form["action"]
        app.logger.debug(action)
        if action == "delkey":
            if request.form["key"] is not None:
                result = r.delete(request.form["key"])
                if result == 1:
                    flash("Key %s has been deleted." % request.form["key"], category="info")
                else:
                    flash("Key %s could not be deleted." % request.form["key"], category="error")
        return redirect(request.url)
    else:
        offset = int(request.args.get("offset", "0"))
        perpage = int(request.args.get("perpage", "10"))
        pattern = request.args.get('pattern', '*')
        dbsize = r.dbsize()
        keys = sorted(r.keys(pattern))
        limited_keys = keys[offset:(perpage + offset)]
        types = {}
        for key in limited_keys:
            types[key] = r.type(key)
        return render_template('keys.html',
                               host=host,
                               port=port,
                               db=db,
                               client_token=client_token,
                               dbsize=dbsize,
                               keys=limited_keys,
                               types=types,
                               offset=offset,
                               perpage=perpage,
                               pattern=pattern,
                               num_keys=len(keys),
                               duration=time.time() - s)


@app.route("/<host>:<int:port>/<int:db>/keys/<key>/")
def key(host, port, db, key):
    """
    Show a specific key.
    key is expected to be URL-safe base64 encoded
    """
    key = base64.urlsafe_b64decode(key.encode("utf8"))
    s = time.time()

    client_token = request.args.get('client_token', default='off', type=str)
    sentinel = request.args.get('sentinel', default='off', type=str)

    r = get_redis(host, port, db, sentinel)

    dump = r.dump(key)
    if dump is None:
        abort(404)
    # if t is None:
    #    abort(404)
    size = len(dump)
    del dump
    t = r.type(key)
    ttl = r.pttl(key)
    if t == "string":
        val = r.get(key).decode('utf-8', 'replace')
    elif t == "list":
        val = r.lrange(key, 0, -1)
    elif t == "hash":
        val = r.hgetall(key)
    elif t == "set":
        val = r.smembers(key)
    elif t == "zset":
        val = r.zrange(key, 0, -1, withscores=True)
    return render_template('key.html',
                           host=host,
                           port=port,
                           db=db,
                           key=key,
                           client_token=client_token,
                           value=val,
                           type=t,
                           size=size,
                           ttl=ttl / 1000.0,
                           now=datetime.utcnow(),
                           expiration=datetime.utcnow() + timedelta(seconds=ttl / 1000.0),
                           duration=time.time() - s)


@app.route("/<host>:<int:port>/<int:db>/pubsub/")
def pubsub(host, port, db):
    """
    List PubSub channels
    """
    s = time.time()

    client_token = request.args.get('client_token', default='off', type=str)
    sentinel = request.args.get('sentinel', default='off', type=str)

    return render_template('pubsub.html',
                           host=host,
                           port=port,
                           db=db,
                           client_token=client_token,
                           sentinel=sentinel,
                           duration=time.time() - s)


def pubsub_event_stream(host, port, db, client_token, sentinel, pattern):
    r = get_redis(host, port, db, sentinel)
    p = r.pubsub()
    p.psubscribe(pattern)
    for message in p.listen():
        if message["type"] != "psubscribe" and message["data"] != "1":
            yield 'data: %s\n\n' % json.dumps(message)


@app.route("/<host>:<int:port>/<int:db>/pubsub/api/")
def pubsub_ajax(host, port, db):
    client_token = request.args.get('client_token', default='', type=str)
    sentinel = request.args.get('sentinel', default='off', type=str)

    return Response(pubsub_event_stream(host, port, db, client_token, sentinel, pattern="*"),
                    mimetype="text/event-stream")


@app.template_filter('urlsafe_base64')
def urlsafe_base64_encode(s):
    if isinstance(s, Markup):
        s = s.unescape()
    elif isinstance(s, bytes):
        s = s.decode('utf-8')

    s = s.encode('utf8')
    s = base64.urlsafe_b64encode(s)
    return Markup(s)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False, port=5001, threaded=True)
