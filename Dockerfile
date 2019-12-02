FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH frankenstrings.frankenstrings.FrankenStrings

# Switch to assemblyline user
USER assemblyline

# Copy FrankenStrings service code
WORKDIR /opt/al_service
COPY . .