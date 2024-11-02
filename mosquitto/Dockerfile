FROM eclipse-mosquitto:latest

# Installation des dépendances
RUN apk add --no-cache \
    git \
    build-base \
    openssl-dev \
    c-ares-dev \
    curl-dev \
    linux-headers \
    libwebsockets-dev \
    util-linux-dev \
    hiredis-dev \
    go \
    gcc \
    musl-dev

# Clone et build du plugin go-auth
RUN git clone https://github.com/iegomez/mosquitto-go-auth.git && \
    cd mosquitto-go-auth && \
    make && \
    make install

# Nettoyage
RUN apk del git build-base go gcc musl-dev

# Configuration par défaut
EXPOSE 8883