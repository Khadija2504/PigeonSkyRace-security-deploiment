FROM jenkins/jenkins:lts

USER root
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    default-jdk \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN curl -L -o keycloak.tar.gz https://github.com/keycloak/keycloak/releases/download/24.0.1/keycloak-24.0.1.tar.gz \
    && tar -xvzf keycloak.tar.gz \
    && mv keycloak-24.0.1 /opt/keycloak \
    && rm keycloak.tar.gz

COPY start-keycloak.sh /opt/start-keycloak.sh
RUN chmod +x /opt/start-keycloak.sh

EXPOSE 8080 8443 50000 8180

ENTRYPOINT ["/opt/start-keycloak.sh"]
