FROM node:22-alpine
WORKDIR /app
COPY --chown=node:node server.mjs /app/server.mjs
RUN mkdir -p /data && chown node:node /data
ENV NODE_ENV=production VAULT_DATA_DIR=/data HOST=0.0.0.0 PORT=8787
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/health').then(async r=>{if(!r.ok||(await r.json()).ok!==true)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "/app/server.mjs"]
