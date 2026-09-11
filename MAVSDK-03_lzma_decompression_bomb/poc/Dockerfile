# MAVSDK-03 reproduction environment.
#
# Uses the SHIPPED release artifact (libmavsdk-dev_3.17.4_debian12_arm64.deb) rather
# than a local build, so the decoder configuration under test is the one users get.
FROM debian:12

ARG MAVSDK_VERSION=3.17.4
ARG MAVSDK_DEB=libmavsdk-dev_3.17.4_debian12_arm64.deb

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl g++ cmake make python3 python3-pip xz-utils procps \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL -o /tmp/${MAVSDK_DEB} \
      https://github.com/mavlink/MAVSDK/releases/download/v${MAVSDK_VERSION}/${MAVSDK_DEB} \
    && apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/${MAVSDK_DEB} \
    && rm -f /tmp/${MAVSDK_DEB} && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages pymavlink

WORKDIR /poc
COPY gcs_app.cpp /poc/
# The deb ships only libmavsdk.so.3.17.4 with no .so symlink, and camera.h includes
# "plugin_base.h" relative to /usr/include/mavsdk -- hence both flags below.
RUN ln -sf /usr/lib/libmavsdk.so.3.17.4 /usr/lib/libmavsdk.so && ldconfig && \
    g++ -O2 -std=c++17 -I/usr/include/mavsdk \
        -o /usr/local/bin/gcs_app /poc/gcs_app.cpp -lmavsdk && \
    test -x /usr/local/bin/gcs_app && echo "gcs_app built OK"

ENV PYTHONUNBUFFERED=1
