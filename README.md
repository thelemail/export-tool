# Thelemail export tool

A standalone command-line tool that downloads your entire [Thelemail](https://thelemail.com) mailbox and decrypts it on your own computer. Thelemail mail is end-to-end encrypted, so the export has to happen client-side: the server never sees your password, your keys, or your messages. The tool handles mailboxes of any size and resumes if it is interrupted.

It works even while an account is suspended, and while it is running it holds a short server-side session so a scheduled deletion will not proceed until you are safely done.

## What it produces

In the output directory, all written with owner-only permissions:

| File | Contents |
| --- | --- |
| `inbox.mbox`, `sent.mbox`, `archive.mbox`, `spam.mbox`, `trash.mbox`, `starred.mbox` | Each folder as a standard mboxrd MBOX file that imports into Apple Mail, Thunderbird, and other clients |
| `folder <name> <id>.mbox` | One MBOX file per folder you made, named after its full path |
| `organization.json` | Your folders and labels with their names, colors and nesting, and which labels each message carries, matched by its `Message-ID` |
| `private-key-encrypted.asc` | Your private key, still encrypted under the passphrase only your password can derive. Never written in the clear |
| `settings.json` | Your account settings and addresses |
| `export-report.json` | What the export contains, and anything it could not get |
| `.export-checkpoint.json` | Resume state. Safe to delete once the export is done |

Attachments are put back into the message they belong to, so every `.mbox` file is
self-contained and an imported message carries its files exactly as it did here. Thelemail
stores attachments as separate encrypted objects rather than inside the message body, so the
tool fetches and decrypts each one and reassembles the MIME message locally.

## When something is missing

The export never claims to be finished when it is not.

Anything the tool could not fetch (a network drop, a rate limit, a server error) is held back
rather than half-written, and listed under `pending` in `export-report.json`. It retries during
the run, and **re-running the same command with the same `--out` retries whatever is left**.

Anything it could fetch but could not read, such as ciphertext that does not decrypt, is listed
under `lost`. The message is still written, with a short note in place of the attachment naming
what is missing.

While either list has anything in it the tool exits non-zero, leaves the server-side export
session open so a scheduled deletion stays on hold, and does not report the export as complete.

## Usage

```bash
export-tool --email you@thelemail.com --out ./my-export
```

| Flag | Meaning |
| --- | --- |
| `--email` | Your Thelemail address. Prompted for if omitted |
| `--out` | Output directory. Default `thelemail-export` |
| `--api` | API base URL. Default `https://api.thelemail.com` |
| `--origin` | Origin header for cookie-authenticated routes. Default `https://app.thelemail.com` |
| `--version` | Print the version and the commit it was built from |

You are prompted for your password and, if two-factor is enabled, for an authenticator or backup code. Re-run the same command with the same `--out` to resume an interrupted export.

## How sign-in works

Authentication is OPAQUE, an augmented PAKE: the password never leaves the machine, and the server never holds anything that a password can be tested against offline. The exchange runs against `/v1/auth/login/init` and `/v1/auth/login/complete` using [`github.com/bytemare/opaque`](https://github.com/bytemare/opaque), pinned to the same version the server runs.

A successful exchange yields the OPAQUE export key. That unwraps the account master key, which derives the OpenPGP passphrase that opens the private key, which decrypts the mail. Every step of that chain has to match the web client exactly, down to the Argon2id profile and the client and server identity strings, or the envelope simply never opens. So before it sends anything the tool fetches the server's published parameters from `/v1/auth/opaque-parameters` and refuses to continue if they differ from the ones it was compiled with; `internal/crypto/opaque_test.go` pins the derivation to vectors taken from the web client's own implementation.

Accounts still on the older SRP scheme are not supported.

## Building from source

Requires the Go version named in `go.mod`.

```bash
make build      # ./bin/export-tool
make test
make lint
make dist       # every release target, into ./dist
```

## Releases

Releases are built only from a signed `v*` tag, by [`.github/workflows/release.yml`](.github/workflows/release.yml). Each one carries the binaries, a source tarball, an SBOM, `release-metadata.json`, and a `SHA256SUMS` covering all of it.

The checksums are signed with Sigstore, and every artifact carries build provenance tying it to the commit and the workflow that produced it:

```bash
cosign verify-blob \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/thelemail/export-tool/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --bundle SHA256SUMS.sigstore.json \
  SHA256SUMS

shasum -a 256 -c SHA256SUMS --ignore-missing

gh attestation verify export-tool-1.0.0-linux-amd64 \
  --repo thelemail/export-tool \
  --signer-workflow thelemail/export-tool/.github/workflows/release.yml
```

A downloaded binary names its own origin, which you can check against the release:

```bash
./export-tool --version
```

### Reproducing a release

The binaries are reproducible. Provenance tells you a release came from a given commit; reproducing it tells you that commit is what the binary actually does. Check out the tag, use the Go version recorded in `release-metadata.json`, and run the same script the workflow runs:

```bash
git checkout v1.0.0
VERSION=1.0.0 COMMIT=$(git rev-parse HEAD) ./scripts/build-release.sh
diff <(sort -k2 dist/SHA256SUMS) <(grep -E 'export-tool-1\.0\.0-(darwin|linux|windows)' SHA256SUMS | sort -k2)
```

The builds are `CGO_ENABLED=0`, `-trimpath` and `-buildvcs=false`, with the build ID cleared, so the output does not depend on where you build it or what your working tree looks like. CI proves this on every run: the `reproducible` job builds twice from two different paths with a cold build cache and fails if the checksums disagree.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Licence

[GNU AGPL v3](LICENSE).
