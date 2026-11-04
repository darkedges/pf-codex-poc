# Existing local Node image, binary verified as v22.23.2. Production image/CVE
# approval is separate; the digest prevents an implicit moving-tag upgrade.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=optional --omit=dev --ignore-scripts --no-audit --no-fund && node -e "import('jose')"

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY src/adapters/pingfederate.ts src/adapters/token-exchange.ts ./src/adapters/
COPY src/policy/client.ts src/policy/contracts.ts src/policy/protocol.ts ./src/policy/
COPY src/copilot/tool-*.ts ./src/copilot/
USER node
ENV NODE_ENV=production TOOL_MODE=verified TOOL_BIND_ADDRESS=0.0.0.0 \
    TOOL_CONFIG_FILE=/run/config/tool-runtime.json TOOL_SECRETS_DIR=/run/secrets TOOL_AUDIT_DIR=/var/lib/tool-audit \
    NODE_EXTRA_CA_CERTS=/run/secrets/tool-outbound-ca.pem
EXPOSE 8443
CMD ["node", "--experimental-strip-types", "src/copilot/tool-main.ts"]
