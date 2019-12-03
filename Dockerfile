FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH frankenstrings.frankenstrings.FrankenStrings

RUN apt-get update && apt-get install -y \
  libyaml-dev \
  python-levenshtein

RUN pip install \
  utils

RUN pip install https://github.com/williballenthin/vivisect/zipball/master
RUN pip install https://github.com/fireeye/flare-floss/zipball/master

# Switch to assemblyline user
USER assemblyline

# Copy FrankenStrings service code
WORKDIR /opt/al_service
COPY . .