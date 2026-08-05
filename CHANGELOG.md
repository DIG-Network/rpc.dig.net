# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-08-05

### Features
- **server:** Serve the path-addressed anonymous content read (/stores/*/content/*) (#15)

## [0.3.0] - 2026-08-04

### Features
- **update:** Auto-update the node nightly, in place over SSM (#14)

## [0.94.0] - 2026-08-04

### Bug Fixes
- **deploy:** Verify the gateway on 443 and count .dig capsules (#13)

## [0.93.9] - 2026-08-03

### Bug Fixes
- **infra:** Persist the origin certificate so a replacement never re-issues (#10)- **infra:** Contain the peek tree, not just check the file type (#12)

## [0.84.0] - 2026-08-03

### Bug Fixes
- **deploy:** Use DIG_NODE_VERSION variable instead of github.ref_name for release tag

## [0.2.4] - 2026-08-03

### Documentation
- **spec:** The capsule object suffix is .dig, not .module (#9)

## [0.2.2] - 2026-08-02

### Bug Fixes
- **release:** Sync Cargo.lock, and add the ecosystem lockfile guard that would have caught it (#8)

## [0.2.1] - 2026-08-02

### Features
- **origin:** Terminate TLS at the gateway so the cutover can use an https-only origin (#6)

### Documentation
- **release:** Record the branch/tag name collision that broke the release (#7)

## [0.1.5] - 2026-08-02

### Bug Fixes
- **deploy:** Wait for the peer network; drop sshd; assert the listener set (#5)

## [0.1.4] - 2026-08-02

### Bug Fixes
- **deploy:** Publish the asset under the name user_data fetches; verify on-host (#4)

## [0.1.3] - 2026-08-02

### Bug Fixes
- **infra:** Pin the state volume AZ to the subnet, not the instance (#3)

## [0.1.2] - 2026-08-02

### Bug Fixes
- **infra:** ASCII-only SG descriptions; peer host is node-rpc.dig.net (#2)

## [0.1.1] - 2026-08-02

### Bug Fixes
- **infra:** Select a dual-stack subnet instead of the first one (#1)

## [0.1.0] - 2026-08-02

### Features
- Rpc.dig.net as a read-tier wrapper over a real public dig-node


