# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: (c) Copyright 2023 Advanced Micro Devices, Inc.
# hadolint global ignore=DL3006,DL3040,DL3041
ARG BUILDER_UBI_IMAGE=redhat/ubi9-minimal:9.3
ARG UBI_IMAGE=redhat/ubi9-micro:9.3

FROM $BUILDER_UBI_IMAGE as builder
ARG SFNT_VERSION
ARG SFNT_BUILD_PARAMS
WORKDIR /opt/sfnettest
COPY src LICENSE /opt/sfnettest/
RUN microdnf install -y make findutils gcc && \
    make $SFNT_BUILD_PARAMS

FROM $UBI_IMAGE
ARG SFNT_VERSION
LABEL \
  name="sfnettest" \
  summary="sfnettest" \
  description="sfnt-stream & sfnt-pingpong" \
  maintainer="Advanced Micro Devices, Inc." \
  vendor="Advanced Micro Devices, Inc." \
  version="$SFNT_VERSION" \
  release="$SFNT_VERSION"
COPY --from=builder /opt/sfnettest/sfnt-stream /opt/sfnettest/sfnt-pingpong /bin/
COPY --from=builder /opt/sfnettest/LICENSE /licenses/
USER 1001
ENV SFNT_AVOID_FORK=1
ENTRYPOINT [ "/bin/sfnt-pingpong" ]
