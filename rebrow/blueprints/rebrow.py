from datetime import datetime, timedelta
from flask import Blueprint, request
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, Markup, Response, json
from flask import current_app as app
from flask import render_template, redirect, url_for
from json import loads as json_loads
from rebrow.sharedlib.metadata import serverinfo_meta
from redis.exceptions import ConnectionError
from redis.sentinel import Sentinel
import base64
import os
import redis
import time

rebrow = Blueprint('rebrow', __name__)

def get_redis(host, port, db, password, sentinel):
  """
  get redis instance
  """
  if sentinel == 'on':
      _sentinel = Sentinel([(host, port)], socket_timeout=0.1)
      return sentinel.master_for(
          'mymaster', db=db, password=password, socket_timeout=0.1)
  else:
      if password == "":
          return redis.StrictRedis(host=host, port=port, db=db)
      else:
          return redis.StrictRedis(host=host, port=port, db=db, password=password)

@rebrow.route("/", methods=['GET', 'POST'])
def login():
    """
    Start page
    """
    if request.method == 'POST':
        host = request.form["host"]
        port = int(request.form["port"])
        port = int(request.form["port"])
        db = int(request.form["db"])
        db = int(request.form["db"])
        url = url_for("rebrow.server_db", host=host, port=port, db=db)
        sentinel = request.form.get("sentinel")
        if sentinel is None:
            sentinel = 'off'
        password = request.form["password"]
        url = url_for("rebrow.server_db", host=host, port=port, db=db, password=password, sentinel=sentinel)
        return redirect(url)
    else:
        s = time.time()
        return render_template('login.html',
                               duration=time.time()-s)


@rebrow.route("/<host>:<int:port>/<int:db>/")
def server_db(host, port, db):
    """
    List all databases and show info on server
    """
    s = time.time()
    try:
        password = request.args.get('password', default = '', type=str)
        sentinel = request.args.get('sentinel', default = 'off', type=str)
        r = get_redis(host, port, db, password, sentinel)
        info = r.info("all")
        dbsize = r.dbsize()
        return render_template('server.html',
                               host=host,
                               port=port,
                               db=db,
                               password=password,
                               info=info,
                               dbsize=dbsize,
                               serverinfo_meta=serverinfo_meta,
                               duration=time.time()-s)
    except ConnectionError as e:
        flash(f'ConnectionError: {e}', category="error")
        return redirect(url_for("rebrow.login"))
    except Exception as e:
        flash(f'Exception: {e}', category="error")
        return redirect(url_for("rebrow.login"))


@rebrow.route("/<host>:<int:port>/<int:db>/keys/", methods=['GET', 'POST'])
def keys(host, port, db):
    """
    List keys for one database
    """
    s = time.time()
    try:
        password = request.args.get('password', default = '', type=str)
        sentinel = request.args.get('sentinel', default = 'off', type=str)
        r = get_redis(host, port, db, password, sentinel)
        if request.method == "POST":
            action = request.form["action"]
            app.logger.debug(action)
            if action == "delkey":
                if request.form["key"] is not None:
                    result = r.delete(request.form["key"])
                    if result == 1:
                        flash("Key %s has been deleted." %
                              request.form["key"], category="info")
                    else:
                        flash("Key %s could not be deleted." %
                              request.form["key"], category="error")
            return redirect(request.url)
        else:
            offset = int(request.args.get("offset", "0"))
            perpage = int(request.args.get("perpage", "10"))
            pattern = request.args.get('pattern', '*')
            dbsize = r.dbsize()
            keys = sorted(r.keys(pattern))
            limited_keys = keys[offset:(perpage+offset)]
            types = {}
            for key in limited_keys:
                types[key] = r.type(key).decode()
            return render_template('keys.html',
                                   host=host,
                                   port=port,
                                   db=db,
                                   password=password,
                                   dbsize=dbsize,
                                   keys=[k.decode() for k in limited_keys],
                                   types=[t.decode() for t in types],
                                   offset=offset,
                                   perpage=perpage,
                                   pattern=pattern,
                                   num_keys=len(keys),
                                   duration=time.time()-s)
    except ConnectionError as e:
        flash(f'ConnectionError: {e}', category="error")
        return redirect(url_for("rebrow.login"))
    except Exception as e:
        flash(f'Exception: {e}', category="error")
        return redirect(url_for("rebrow.login"))


@rebrow.route("/<host>:<int:port>/<int:db>/keys/<key>/")
def key(host, port, db, key):
    """
    Show a specific key.
    key is expected to be URL-safe base64 encoded
    """
    key = base64.urlsafe_b64decode(key.encode("utf8"))
    s = time.time()
    try:
        password = request.args.get('password', default = '', type=str)
        sentinel = request.args.get('sentinel', default = 'off', type=str)
        r = get_redis(host, port, db, password, sentinel)
        dump = r.dump(key)
        if dump is None:
            abort(404)
        # if t is None:
        #    abort(404)
        size = len(dump)
        del dump
        t = r.type(key)
        ttl = r.pttl(key)
        if t == b"string":
            val = r.get(key).decode("utf-8", "replace")
            try:
                val = json.dumps(json_loads(val), indent=3)
            except ValueError:
                pass
        elif t == b"list":
            val = r.lrange(key, 0, -1)
        elif t == b"hash":
            val = r.hgetall(key)
        elif t == b"set":
            val = r.smembers(key)
        elif t == b"zset":
            val = r.zrange(key, 0, -1, withscores=True)
        return render_template('key.html',
                               host=host,
                               port=port,
                               db=db,
                               password=password,
                               key=key.decode(),
                               value=val,
                               type=t.decode(),
                               size=size,
                               ttl=ttl / 1000.0,
                               now=datetime.utcnow(),
                               expiration=datetime.utcnow() + timedelta(seconds=ttl / 1000.0),
                               duration=time.time()-s)
    except ConnectionError as e:
        flash(f'ConnectionError: {e}', category="error")
        return redirect(url_for("rebrow.login"))
    except Exception as e:
        flash(f'Exception: {e}', category="error")
        return redirect(url_for("rebrow.login"))


@rebrow.route("/<host>:<int:port>/<int:db>/pubsub/")
def pubsub(host, port, db):
    """
    List PubSub channels
    """
    s = time.time()
    password = request.args.get('password', default = '', type=str)
    sentinel = request.args.get('sentinel', default = 'off', type=str)
    return render_template('pubsub.html',
                           host=host,
                           port=port,
                           db=db,
                           password=password,
                           sentinel=sentinel,
                           duration=time.time()-s)


def pubsub_event_stream(host, port, db, password, sentinel, pattern):
    r = get_redis(host, port, db, password, sentinel)
    p = r.pubsub()
    p.psubscribe(pattern)
    for message in p.listen():
        if message["type"] != "psubscribe" and message["data"] != "1":
            yield 'data: %s\n\n' % json.dumps(message)


@rebrow.route("/<host>:<int:port>/<int:db>/pubsub/api/")
def pubsub_ajax(host, port, db):
    try:
        password = request.args.get('password', default = '', type=str)
        sentinel = request.args.get('sentinel', default = 'off', type=str)

        return Response(pubsub_event_stream(host, port, db, password, sentinel, pattern="*"),
                        mimetype="text/event-stream")
    except ConnectionError as e:
        flash(f'ConnectionError: {e}', category="error")
        return redirect(url_for("rebrow.login"))
    except Exception as e:
        flash(f'Exception: {e}')
        return redirect(url_for("rebrow.login"))
