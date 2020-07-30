FROM python:3.8.3-slim-buster

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    apt-utils; \
    pip install --no-cache-dir pipenv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 8000

WORKDIR /app

COPY src/Pipfile src/Pipfile.lock ./

RUN pipenv install

COPY src ./

ENV PYTHONPATH /app

CMD [ "bash", "startup.sh" ]
