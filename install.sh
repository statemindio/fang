#!/bin/bash

git clone https://github.com/llvm/llvm-project.git
cd ./llvm-project || exit

# TODO: check if cmake is installed
cmake -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -S llvm -B build

NPROC=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc)

cmake --build build --parallel $NPROC
export CLANG_BIN=$(pwd)/build/bin/clang

uname="$(uname)"

if [[ "$uname" == "Darwin" ]]; then
  brew install bazel
elif [[ "$uname" == "Linux" ]]; then
  sudo apt install apt-transport-https curl gnupg -y
  curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
  sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
else
  exit 1
fi

pip install -r requirements.txt
