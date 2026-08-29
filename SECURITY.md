# Security policy

## Reporting a vulnerability

Send reports to **security@thel.email**. A PGP key is available on request.

Please include enough detail to reproduce the issue: affected version or commit, the steps involved, and what an attacker gains. If you have a proof of concept, include it.

We aim to acknowledge a report within three working days and to keep you updated as we work on a fix. Please give us a reasonable opportunity to release one before disclosing publicly.

Do not test against other people's accounts or mailboxes. Register your own account for testing.

## Scope

This repository is the command-line export tool. It authenticates as the account owner and decrypts a whole mailbox on the owner's machine. Findings that are in scope here include:

- Anything that causes the password, the OPAQUE export key, the account master key, or the decrypted private key to leave the machine or reach the server
- Weaknesses in the OPAQUE exchange as implemented here, including the pinned Argon2id profile, the client and server identity binding, and the derivation from the export key to the OpenPGP passphrase
- Accepting a server-supplied parameter set, wrapped master key, or private key that a correct client would reject
- Writing decrypted mail, keys, or resume state to a location or with permissions that expose it to other users of the machine
- A published binary whose build provenance does not match the commit it claims, or any other break in the chain from a downloaded release back to this source
- Path traversal or similar through server-controlled values that end up in output filenames

Server-side issues belong to the backend rather than this repository, but report them to the same address and we will route them.

## Out of scope

- Reports that the tool trusts the operator of the machine it runs on. It decrypts your mail; anyone who already controls your account or your machine has won
- Automated scanner output without a working proof of concept
- Denial of service through volume alone
- Social engineering, and physical attacks
- Vulnerabilities in dependencies with no demonstrated path to exploitation here
