FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH frankenstrings.frankenstrings.FrankenStrings

USER root

RUN apt-get update && apt-get install -y libyaml-dev && rm -rf /var/lib/apt/lists/*

RUN pip install utils pefile python-magic beautifulsoup4 lxml  && rm -rf ~/.cache/pip

# Switch to assemblyline user
USER assemblyline

# Copy FrankenStrings service code
WORKDIR /opt/al_service
COPY . .