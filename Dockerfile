FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config \
    curl libjsoncpp-dev libjsonrpccpp-dev \
    libssl-dev libzip-dev  \
    libpq-dev libpqxx-dev

WORKDIR /app
COPY . /app

#RUN mkdir build/ && cd build/ && cmake -S .. && cmake --build . -j4
#CMD ["./bin/sec-chat-server -c ./sec-chat-server-settings.json"]
