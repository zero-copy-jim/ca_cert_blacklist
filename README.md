# ca_cert_blacklist

Distrust the roots behind the compromised eMudhra intermediate CAs on RHEL and Fedora-family hosts, verify the result, and roll it back once your vendor ships a fixed `ca-certificates` package.

In October 2026 the private keys of eight eMudhra intermediate CAs were compromised. Browsers blocked them within hours; system trust stores are still catching up. Background: Red Hat [RHSB-2026-012](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012) and the [incident summary](https://emudhra.we-have-a-problem.com/).

## What it does

Adds these roots to the system blocklist using `trust` and `update-ca-trust`, then checks they are gone from the TLS bundle:

- `emSign ECC Root CA - G3`
- `Comodo AAA Services root` (the cross-signed path; skip with `BLOCK_AAA=0`)

## Supported systems

Written for RHEL 7, 8, 9 and 10. Should work on other distros that use p11-kit `trust` and `update-ca-trust` (Fedora, CentOS Stream, Rocky, AlmaLinux). Not RHEL 6, which has no `trust` command.

## Usage

```bash
curl -O https://raw.githubusercontent.com/zero-copy-jim/ca_cert_blacklist/main/block-cert.sh
chmod +x block-cert.sh

./block-cert.sh --check            # report only, no root needed
sudo ./block-cert.sh               # block both roots, then verify
sudo BLOCK_AAA=0 ./block-cert.sh   # block only the emSign root
sudo ./block-cert.sh --undo        # remove the blocklist entries
```

`--check` exits `0` when the roots are no longer trusted for TLS and `2` when they still are, so it drops straight into Ansible, Salt or CI. Use the same `BLOCK_AAA` value for `--check` that you used to apply.

The script is safe to re-run, and Red Hat's updated `ca-certificates` package can be installed on top later.

## Before you run it

- Blocking `Comodo AAA Services root` can break services that still chain to legacy Sectigo roots, so test first. `BLOCK_AAA=0` avoids that, but leaves the cross-signed path to the compromised intermediates trusted.
- Restart long-running services (Java apps, nginx, httpd, proxies) afterwards so they reload the trust store.
- This only changes the system trust store. Software with its own bundle (Node.js, Python `certifi`, bundled JDKs, appliances) needs its own fix.

## Verify

```bash
curl https://dv-g3b-emudhra.we-have-a-problem.com/
curl https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

A certificate error from both means the host no longer trusts the compromised intermediates.

## License

MIT
