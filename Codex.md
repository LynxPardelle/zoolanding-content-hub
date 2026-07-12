# Zoolanding Content Hub Notes

Compatibility pointer for older agents:

- Read [AGENTS.md](AGENTS.md) for task routing and safety boundaries.
- Read [README.md](README.md) for the current service contract and verification commands.
- Open [changelog/](changelog/) only when historical evidence is needed.

Durable repository decisions not repeated in the service contract:

- Article packages and published bundles use deterministic `content-hubs/{environment}/{hubId}/...` S3 prefixes; DynamoDB holds compact indexes and workflow metadata.
- Browser-facing media must be unsigned public URLs or explicitly approved CDN URLs. Signed URLs are rejected from public projections.
- Publishing creates validated bundles and metadata. Propagation into Angular `runtime.contentHubs.publicArticles` remains a separate runtime-read/front-door integration unless explicitly wired.
