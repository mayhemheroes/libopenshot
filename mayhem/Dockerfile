FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang software-properties-common
RUN add-apt-repository ppa:openshot.developers/libopenshot-daily
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git cmake \
    pkg-config \
    libopenshot-audio-dev \
    libx11-dev \
    libfreetype6-dev \
    libasound2-dev \
    libavcodec-dev \
    libavformat-dev \
    libavutil-dev \
    libswresample-dev \
    libswscale-dev \
    libpostproc-dev \
    libfdk-aac-dev \
    libjsoncpp-dev \
    libzmq3-dev \
    qtbase5-dev \
    libqt5svg5-dev \
    libbabl-dev \
    libopencv-dev \
    libprotobuf-dev \
    protobuf-compiler swig \
    libmagick++-dev

RUN git clone https://github.com/OpenShot/libopenshot-audio/
WORKDIR /libopenshot-audio
RUN cmake -B build -S . -DENABLE_PYTHON=0 -DENABLE_RUBY=0 -DENABLE_TESTS=0
RUN cmake --build build
RUN cmake --install build

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_stringToJson.cpp -fsanitize=fuzzer,address -I /install/include/libopenshot/ -I /usr/include/jsoncpp/ /install/lib/libopenshot.so -ljsoncpp -o /fuzz

FROM ubuntu:22.04 as package

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git cmake software-properties-common clang
RUN add-apt-repository ppa:openshot.developers/libopenshot-daily
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y pkg-config \
    libopenshot-audio-dev \
    libx11-dev \
    libfreetype6-dev \
    libasound2-dev \
    libavcodec-dev \
    libavformat-dev \
    libavutil-dev \
    libswresample-dev \
    libswscale-dev \
    libpostproc-dev \
    libfdk-aac-dev \
    libjsoncpp-dev \
    libzmq3-dev \
    qtbase5-dev \
    libqt5svg5-dev \
    libbabl-dev \
    libopencv-dev \
    libprotobuf-dev \
    protobuf-compiler swig \
    libmagick++-dev

RUN git clone https://github.com/OpenShot/libopenshot-audio/
WORKDIR /libopenshot-audio
RUN cmake -B build -S . -DENABLE_PYTHON=0 -DENABLE_RUBY=0 -DENABLE_TESTS=0
RUN cmake --build build
RUN cmake --install build

COPY --from=builder /install/lib/* /deps/
COPY --from=builder /fuzz /fuzz_stringToJson
ENV LD_LIBRARY_PATH=/deps

