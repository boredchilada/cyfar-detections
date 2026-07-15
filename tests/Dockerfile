FROM jasonish/suricata:7.0

USER root

RUN dnf install -y python3 python3-pip python3-pyyaml && \
    dnf clean all && \
    pip3 install scapy

WORKDIR /validator

COPY craft_pcap.py validate.py ./

ENTRYPOINT ["python3", "validate.py"]
