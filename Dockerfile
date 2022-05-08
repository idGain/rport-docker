FROM alpine:3.15 as downloader

ARG rport_version=0.6.3
ARG frontend_build=0.6.0-build-966
ARG NOVNC_VERSION=1.3.0

RUN apk add unzip

WORKDIR /app/

RUN wget -q https://github.com/cloudradar-monitoring/rport/releases/download/${rport_version}/rportd_${rport_version}_Linux_x86_64.tar.gz -O rportd.tar.gz \
     && tar xzf rportd.tar.gz rportd
RUN wget -q https://downloads.rport.io/frontend/stable/rport-frontend-stable-${frontend_build}.zip -O frontend.zip \
    && unzip frontend.zip -d ./frontend
RUN wget https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.zip -O novnc.zip \
    && unzip novnc.zip && mv noVNC-${NOVNC_VERSION} ./novnc

WORKDIR /envplate
RUN set -e \
    && arch=$(uname -m) \
    && if [ "${arch}" == "aarch64" ]; then release_arch="arm64"; else release_arch=${arch}; fi \
    && release_name=envplate_1.0.2_$(uname -s)_${release_arch}.tar.gz \
    && wget https://github.com/kreuzwerker/envplate/releases/download/v1.0.2/${release_name} -O envplate.tar.gz \
    && tar -xf envplate.tar.gz

FROM debian:11

COPY --from=downloader /app/rportd /usr/local/bin/rportd
COPY --from=downloader /app/frontend/ /var/www/html/
COPY --from=downloader /app/novnc/ /var/lib/rport-novnc
COPY --from=downloader /envplate/envplate /usr/local/bin/ep

COPY entrypoint.sh /entrypoint.sh

RUN set -e \
    && useradd -d /var/lib/rport -m -U -r -s /bin/false rport \
    && mkdir -p /etc/rport && chown rport:rport /etc/rport

USER rport

COPY --chown=rport:rport rportd.conf.template /etc/rport/rportd.conf.template

VOLUME [ "/var/lib/rport/" ]

EXPOSE 8080
EXPOSE 3000

ENTRYPOINT [ "/bin/bash", "/entrypoint.sh", "/usr/local/bin/rportd", "--data-dir", "/var/lib/rport", "--config", "/etc/rport/rportd.conf" ]
