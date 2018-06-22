FROM tianon/true
LABEL maintainer="Cyril Dangerville <http://scr.im/cdan>"
LABEL org.label-schema.schema-version = "1.0"
LABEL org.label-schema.vendor = "Thales Services"

ARG VERSION=0.2.1-SNAPSHOT

ADD target/authzforce-ce-kafka-extensions-${VERSION}-bin.tar.gz /authzforce-ce-kafka-extension




