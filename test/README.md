# Tests for rebrow

This folder should contain, at one point, automated tests for rebrow. Currently it serves the purpose to deterministically create redis content as a basis for manual tests and development.

## Running the test setup

To run a test setup, you need `docker` and `docker-compose`. Then, in the current directory, do this:

```
$ docker-compose up
```

No reach rebrow via `http://<your-docker-ip>:5001/redis:0/`.

## Adding tests

You can simply add test datasets to `fillredis/fill.sh` via Pull Requests.
