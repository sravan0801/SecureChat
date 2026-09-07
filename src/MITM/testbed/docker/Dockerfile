# One image, used for all three roles (Alice / Bob / Trudy).
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      g++ make libssl-dev openssl ca-certificates \
      tcpdump iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work/src/MITM
CMD ["sleep", "infinity"]
