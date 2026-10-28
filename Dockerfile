# Local simulation image only. Do not deploy this image to production.
FROM node:22.16.0-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
USER node
ENV DEMO_ONLY=true HOST=0.0.0.0 COPILOT_MODE=mock M365_MODE=mock
CMD ["node","--experimental-strip-types","src/services/gateway-1.ts"]
