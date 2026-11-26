FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    TERM=xterm \
    JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
    CONTIKI=/root/contiki-3.0 \
    QT_X11_NO_MITSHM=1 \
    PATH=/usr/local/msp430/bin:/usr/local/bin:/usr/lib/jvm/java-8-openjdk-amd64/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# Enable i386 architecture for precompiled 32-bit mspgcc 4.7.2 toolchain
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        curl \
        git \
        unzip \
        bzip2 \
        sudo \
        vim \
        nano \
        python3 \
        gdb \
        procps \
        net-tools \
        iproute2 \
        # Section 2.1: Java 8 & Ant for Cooja
        openjdk-8-jdk \
        ant \
        # Section 2.3: Build essential & MSP430 packages + 32-bit runtime libs
        build-essential \
        binutils-msp430 \
        gcc-msp430 \
        msp430-libc \
        msp430mcu \
        mspdebug \
        libc6:i386 \
        libncurses5:i386 \
        libstdc++6:i386 \
        zlib1g:i386 \
        # Section 2.4: Qt5 framework, QtSerialPort, Qt Creator & Mesa OpenGL
        qt5-default \
        qtbase5-dev \
        qtbase5-dev-tools \
        qtchooser \
        qt5-qmake \
        libqt5serialport5-dev \
        qtcreator \
        libgl1-mesa-dev \
        # X11 / XCB / Swing / Headless GUI support
        libxcb-xinerama0 \
        libxkbcommon-x11-0 \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-randr0 \
        libxcb-render-util0 \
        libxcb-shape0 \
        libxtst6 \
        libxi6 \
        libxrender1 \
        fonts-dejavu-core \
        dbus-x11 \
        x11-apps \
        xvfb && \
    update-java-alternatives -s java-1.8.0-openjdk-amd64 || true && \
    rm -rf /var/lib/apt/lists/*

# Install MSP430-GCC 4.7.2 (mspgcc dev 20120911) with 20-bit MSP430X support for Sky & Z1 motes
RUN (wget -q -O /tmp/mspgcc.tar.bz2 https://github.com/simonduq/simonduq.github.io/raw/master/resources/mspgcc-4.7.2-compiled.tar.bz2 || \
     wget -q -O /tmp/mspgcc.tar.bz2 https://simonduq.github.io/resources/mspgcc-4.7.2-compiled.tar.bz2) && \
    tar -xjf /tmp/mspgcc.tar.bz2 -C /tmp/ && \
    cp -f -r /tmp/msp430/* /usr/local/ && \
    rm -rf /tmp/msp430 /tmp/mspgcc.tar.bz2 && \
    msp430-gcc --version

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    ANT_OPTS="-Dfile.encoding=UTF-8"

# Section 2.1 & 4.5: Obtain Contiki OS 3.0 + MSPSim, pre-compile Cooja, and create convenience links/copies
RUN git config --global url."https://github.com/".insteadOf "git://github.com/" && \
    git config --global url."https://".insteadOf "git://" && \
    git clone --branch 3.0 --depth 1 https://github.com/contiki-os/contiki.git /root/contiki-3.0 && \
    cd /root/contiki-3.0 && \
    sed -i 's|git://github.com/|https://github.com/|g; s|git://|https://|g' .gitmodules && \
    git submodule sync && \
    (git submodule update --init --recursive || \
     (rm -rf /root/contiki-3.0/tools/mspsim && git clone https://github.com/contiki-os/mspsim.git /root/contiki-3.0/tools/mspsim)) && \
    cd /root/contiki-3.0/tools/cooja && \
    ant jar && \
    ln -s /root/contiki-3.0 /root/contiki && \
    mkdir -p /root/contiki-3.01 && \
    tar -C /root/contiki-3.0 --exclude='.git' -cf - . | tar -C /root/contiki-3.01 -xf -

WORKDIR /root/idit-sdn

# Keep host x86_64 binutils (as/ld/ar) unshadowed while /usr/local/bin provides msp430-gcc 4.7.2
ENV PATH=/usr/local/bin:/usr/lib/jvm/java-8-openjdk-amd64/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

# Fix Contiki 3.0 contiki-z1-main.c compatibility with PROCESS_CONF_NO_PROCESS_NAMES=1
RUN sed -i 's/(\*processes)->name/PROCESS_NAME_STRING(*processes)/g' \
        /root/contiki-3.0/platform/z1/contiki-z1-main.c \
        /root/contiki-3.01/platform/z1/contiki-z1-main.c

COPY . /root/idit-sdn
RUN chmod +x /root/idit-sdn/applications/compile.sh /root/idit-sdn/simulation/run_simulations.sh

CMD ["tail", "-f", "/dev/null"]
