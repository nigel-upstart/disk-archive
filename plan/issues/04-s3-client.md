<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/4 (synchronized during PR #9). The issue is the source of truth; git rm this file when #4 closes or if it drifts. -->

# #4: S3 client via aws-sdk-s3 + aws-config (profiles, SSO, retries, corporate CA)

Part of #1. **Blocked by** #2. Land the shared `ObjectStore`/in-process S3 mock seam early for #3's tests; complete production pipeline integration after #3's implementation merges, without waiting for #3's final profiling/performance acceptance or issue closure.

## Scope

Replace boto3, and the previously planned AWS CLI v2 subprocess backend, with the AWS SDK for Rust behind a storage trait that tests can fake.

### Crates
- `aws-config` with `default-features = false`; enable `default-https-client`, `rt-tokio`, and `sso`, but never `credentials-process`. Check the resolved feature graph to prevent transitive re-enablement. Profiles requiring `credential_process` are unsupported; normal environment, shared-file, SSO, and role providers remain available. Version 1.13.x when this was written.
- `aws-sdk-s3` with `behavior-version-latest` (1.153.x when this was written).
- Build **one** shared `aws_sdk_s3::Client` and clone it as needed (clones are cheap). This replaces the legacy per-thread clients.

### Configuration (no defaults that identify a user)
- `DISK_ARCHIVE_AWS_PROFILE` (optional) and `DISK_ARCHIVE_REGION` (optional) map to `aws_config::defaults(BehaviorVersion::latest()).profile_name(..).region(..)`. If they are unset, use the standard provider chain.
- The bucket and key prefix are required (`DISK_ARCHIVE_BUCKET`, `DISK_ARCHIVE_PREFIX`). If either is missing the program exits with an error.
- SSO profiles work after `aws sso login` (the token cache is shared with the CLI). Document this in the README.

### Reliability
- Adaptive retries with up to 8 attempts, matching the legacy botocore config.
- Explicit connect timeout and per-attempt operation timeout, both from config.
- Stalled-stream protection enabled.

### TLS behind corporate interception proxies
- The legacy version needed `truststore` to trust OS-installed corporate roots. The SDK's default HTTPS client (`aws-smithy-http-client` `default-client`) loads OS roots through `rustls-native-certs`.
- Verify this on macOS with a corporate root in the system keychain.
- If that is not enough, support an explicit CA bundle (`DISK_ARCHIVE_CA_BUNDLE`, falling back to `AWS_CA_BUNDLE`) through a custom HTTP client.

### `ObjectStore` trait
- Methods:
  - `put_object_verified(path, key, metadata) -> VerifiedUpload`, which delegates large objects to #5
  - `head(key)`
  - `put_manifest(key, bytes)`
- Implementations:
  - `SdkStore` (production)
  - an in-process S3 mock on localhost for tests, either `s3s-fs` or the `s3-mock-server` from the transfer-manager repo, so tests exercise real HTTP and SigV4
- No `Command` or `tokio::process` in this module (enforced by ast-grep).
- Server-side encryption is `AES256`, as in the legacy version.

## Acceptance criteria

- [ ] Integration tests against the mock cover put, head (size, metadata and checksum), manifest upload, retryable 5xx errors and throttling.
- [ ] A test shows a corrupted or mismatched head response produces no `VerifiedUpload` and no delete.
- [ ] Profile and region config is covered by tests (env only, `.env` only, flag override). A profile containing `credential_process` cannot spawn a command, and the resolved build excludes that feature.
- [ ] Manual smoke against a real bucket under a dedicated test prefix is documented (not run in CI, needs credentials).
- [ ] The corporate-proxy TLS behavior is verified and documented.
