FROM ubuntu:20.04
RUN apt-get update && apt-get -y install wget unzip openjdk-11-jdk tmux
WORKDIR /root/deps
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.2.3_build/ghidra_9.2.3_PUBLIC_20210325.zip
RUN unzip ghidra_9.2.3_PUBLIC_20210325.zip && rm ghidra_9.2.3_PUBLIC_20210325.zip
RUN sed -i "9c MAXMEM=4G" ./ghidra_9.2.3_PUBLIC/ghidraRun
COPY ./static_analysis /root/findtrace
WORKDIR /root
RUN chmod -R +x ./

COPY ./dynamic_analysis /root/uniFuzzGo

RUN apt-get update && \ 
    apt-get install -y libc6-armel-cross gcc-arm-linux-gnueabi libc6-mipsel-cross gcc-mipsel-linux-gnu && \
    apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools python python-setuptools && \
    apt-get install -y lld llvm llvm-dev clang && \
    apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev && \
    apt-get  install -y python3-pip
    
WORKDIR /root/
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && \
    git clone https://github.com/Battelle/afl-unicorn
    
WORKDIR /root/AFLplusplus
RUN make all && make install
 
WORKDIR /root/afl-unicorn/unicorn_mode
RUN wget https://bootstrap.pypa.io/ez_setup.py -O - | python
RUN sed -i '120,122d' ./build_unicorn_support.sh
RUN wget https://github.com/unicorn-engine/unicorn/archive/refs/tags/1.0.3.zip
RUN unzip 1.0.3.zip && rm 1.0.3.zip && mv unicorn-1.0.3 unicorn
RUN ./build_unicorn_support.sh

RUN pip3 install --upgrade "pip<21.0.0" && \
    pip3 install pwntools==4.8.0 && \
    pip3 install angr==9.2.6 && \
    pip3 install tqdm

ADD ./deps/tracer.py /usr/local/lib/python3.8/dist-packages/angr/exploration_techniques/tracer.py
ADD ./deps/asm.py /usr/local/lib/python3.8/dist-packages/pwnlib/asm.py
ADD ./deps/base.py /usr/local/lib/python3.8/dist-packages/claripy/ast/base.py

WORKDIR /root/uniFuzzGo
RUN make
