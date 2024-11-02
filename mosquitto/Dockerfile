FROM eclipse-mosquitto:latest

RUN apk add --no-cache \
    git \
    build-base \
    openssl-dev \
    c-ares-dev \
    curl-dev \
    linux-headers \
    libwebsockets-dev \
    util-linux-dev \
    hiredis-dev

RUN git clone https://github.com/iegomez/mosquitto-go-auth.git && \
    cd mosquitto-go-auth && \
    make && \
    make install

RUN apk del git build-base