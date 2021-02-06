# encoding: utf8

from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, Markup, Response, json
import redis
import time
from datetime import datetime, timedelta
from json import loads as json_loads
import os
import base64

from rebrow.blueprints.rebrow import rebrow

app = Flask(__name__)

# key for cookie safety. Shal be overridden using ENV var SECRET_KEY
app.secret_key = os.getenv("SECRET_KEY", "lasfuoi3ro8w7gfow3bwiubdwoeg7p23r8g23rg")

app.register_blueprint(rebrow)

@app.template_filter('urlsafe_base64')
def urlsafe_base64_encode(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = base64.urlsafe_b64encode(s.encode("utf8"))
    return Markup(s.decode("utf8"))

def main():
    app.run(host="0.0.0.0", debug=False, port=5001, threaded=True)

if __name__ == "__main__":
    main()