# MAVROS-02 reproduction environment.
#
# Deliberately uses the SHIPPED Debian package (ros-jazzy-mavros), not a source
# build. That matters: the package is compiled Release with NDEBUG defined, which
# is exactly the condition under which rcpputils::assert_true() compiles to
# `(void) condition;` and the bounds check guarding std::advance(write_it, ...)
# disappears. A source build configured Debug would NOT reproduce the OOB read --
# it would throw instead.
FROM ros:jazzy-ros-base

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ros-jazzy-mavros \
      ros-jazzy-mavros-msgs \
      geographiclib-tools \
      python3-pip \
      gdb \
    && rm -rf /var/lib/apt/lists/*

# mavros refuses to start without the geoid dataset.
RUN /opt/ros/jazzy/lib/mavros/install_geographiclib_datasets.sh || true

RUN pip3 install --no-cache-dir --break-system-packages pymavlink

WORKDIR /poc
COPY poc_MAVROS02_ftp_write_ack_oob.py ftp_client.py /poc/
ENV PYTHONUNBUFFERED=1
