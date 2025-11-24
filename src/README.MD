# Self Hosting / Build Your Own Docker Image

The source code is provided for those who run in environments without access to `hub.docker.com`

- This application was developed with Python 3.11.6
- Install requirements.txt
- This application requires a Redis Server instance listening on port 6379
- Edit `async_main.conf` with your cluster's information
- Launch application with `hypercorn async_main:app --workers 4 --bind 127.0.0.1:4000`

## If you'd like to build your own Docker image then edit the following values in `async_main.py`:

- Change `config.read("async_main.conf")` to match your `docker-compose.yml`'s `volumes` declarations
- Change `redis_host = 'localhost'` to `redis_host = 'redis'`