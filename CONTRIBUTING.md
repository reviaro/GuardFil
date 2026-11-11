# Contributing to GuardFil

Thank you for helping. A few rules keep the project's licensing clear.

- **License of contributions.** GuardFil is licensed under the GNU AGPL v3
  ([LICENSE](LICENSE)). By sending a contribution you agree that it is
  licensed under the same terms.
- **Sign-off.** Add a `Signed-off-by: Your Name <you@example.com>` line to
  each commit (`git commit -s`). It certifies the
  [Developer Certificate of Origin](https://developercertificate.org/): you
  wrote the change, or otherwise have the right to submit it under this
  license.
- **Security issues.** Do not open a public issue for a vulnerability. Report
  it privately as described in [SECURITY.md](SECURITY.md).
- **Tests.** Run `go test ./...` and the Python tests listed in
  `.github/workflows/ci.yml` before sending a change. Security fixes need a
  regression test.
