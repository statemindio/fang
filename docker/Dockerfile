FROM fuzzer/llvm:v0.0.1

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt upgrade -y
RUN apt install apt-transport-https curl gnupg -y
RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
RUN mv bazel-archive-keyring.gpg /usr/share/keyrings
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
RUN apt update && apt install -y bazel

RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt install -y python3.10-dev
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10

RUN mkdir -p /app
WORKDIR /app

RUN apt install -y git

COPY ../ .

RUN pip3.10 install -r requirements.txt

#CMD PYTHONPATH=/app python tests/integration_runner/generate.py
