# Fence Dynamic Buckets Documentation

This documentation describes the implementation and usage of dynamic bucket management in Fence. It covers the database schema, API endpoints, integration points, OpenAPI additions, and important guardrails for secure and maintainable operation.

## Table of Contents

1. [Architecture Overview](./ARCHITECTURE_OVERVIEW.md)
2. [Use Cases](./use_cases.md)
3. [Dynamic Bucket Configuration](./DYNAMIC_BUCKET_CONFIG.md)
4. [Database Schema](./FENCE_CHANGES_Implementation.md#1-database-schema-sql)
5. [Admin API Endpoints](./FENCE_CHANGES_Implementation.md#2-endpoint-specs-adminonly)
6. [Integration Points in Fence](./FENCE_CHANGES_Implementation.md#3-patch-points-in-fence-swap-config-lookups--registry-accessor)
7. [OpenAPI Additions](./FENCE_CHANGES_Implementation.md#4-minimal-openapi-additions-merge-into-fence-spec)
8. [Guardrails & Notes](./FENCE_CHANGES_Implementation.md#5-guardrails--notes)
9. [Secrets Implementation](./SECRETS_Implementation.md)
10. [Acceptance Tests](./ACCEPTANCE_TESTS.md)

Start with the architecture overview and use cases, then review configuration, schema, and endpoints. Continue with integration points, OpenAPI changes, guardrails, secrets, and acceptance tests.
