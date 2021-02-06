rebrow-modernized - Python-Flask-based Browser for Redis Content
=====================================================

![Start screen](https://farm4.staticflickr.com/3913/14615623267_c4a38b4fe1_c.jpg)

Built for the developer who needs to look into a Redis store.
Allows for inspection and deletion of keys and follows PubSub messages. Also displays
some runtime and configuration information.

## Fork Info

I'm Jon D. Kelley and forked this because the upstream was abandoned.
I've added some features for my workplace at [LogDNA](https://logdna.com/).

In the spirit of open source here are my goals:

* Upgrade for Python3 (unicode support) ✅
* Move the code into Flask blueprint pattern. ✅
* Add docker-compose file with a Redis instance for testing. ✅
* Bump flask dependency from 1.0 to 1.1.0 ✅
* Add (*optional*) password support for Redis instances (thanks to [kveroneau](https://github.com/kveroneau))

## Primary Features

* Web based
* Runs in Python 3.9.1
* Lightweight requirements
* Search for keys using patterns
* Delete single keys
* Show PubSub messages
* Show server statistics

## Quick Start

Execute this:

    git clone https://github.com/marians/rebrow.git
    cd rebrow
    virtualenv venv
    source venv/bin/activate
    python3 setup.py install
    rebrow &

Then open [127.0.0.1:5001](http://127.0.0.1:5001).

## Running in docker-compose

If you have docker-compose installed, you can simply run

```
docker-compose build
docker-compose up
```

Then open [127.0.0.1:5001](http://127.0.0.1:5001).

A redis server is started in tandem with hostname `redis` for your convienence.

## Running as Docker container

If you run redis in a Docker container, the recommended way is to run rebrow in it's own Docker container, too.

You can use the ready-made public image [marian/rebrow](https://registry.hub.docker.com/u/marian/rebrow/).

Alternatively, the provided `Dockerfile` can be used to create the according image. The `Makefile` contains example commands to build the image and run a container from the image.

When running the image, make sure to get your links right. For example, if your redis server is running in a container named `myredis`, start your rebrow container like this:

```
docker run --rm -ti -p 5001:5001 --link myredis:myredis jondkelley/rebrow:latest
```

Then access rebrow via `http://<your-docker-ip>:5001/` and set the host name in the login screen to `redis` or your Redis instance if it's something else..

## Contributers

* 2014 Marian Steinbach
* 2021 Jonathan Kelley

## License

MIT licensed. See file LICENSE for details.

## Screenshots

![Start screen](https://farm4.staticflickr.com/3913/14615623267_c4a38b4fe1_c.jpg)

![Server status](https://farm3.staticflickr.com/2897/14615432280_b379e0f0af_c.jpg)

![Command stats](https://farm4.staticflickr.com/3902/14801787802_0c9b518f32_c.jpg)

![All Keys](https://farm4.staticflickr.com/3887/14615526428_ea251f2600_c.jpg)

![Keys matching a pattern](https://farm4.staticflickr.com/3887/14615482059_dda867f87f_c.jpg)

![Key details](https://farm6.staticflickr.com/5574/14779149896_f7194f0f7c_c.jpg)

