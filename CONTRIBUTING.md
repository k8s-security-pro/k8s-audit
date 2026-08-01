# Contributing to k8s-audit

Thanks for helping make Kubernetes clusters safer. This project stays deliberately
small and dependency-light, so contributions are easy to review and easy to trust.

## Ground rules for a check

Every check must be:

- **`kubectl` + `jq` only.** No extra binaries, no cloud SDKs, no network calls.
- **Read-only.** A check must never mutate the cluster. We only ever `get`/`list`.
- **High-signal.** It should catch a real, common misconfiguration — not a stylistic nit.
  If a well-run cluster trips it constantly with no security consequence, it's noise.
- **Mapped to a domain.** Tie it to one of the nine domains of the
  [k8s-security.pro 50-point checklist](https://k8s-security.pro) and give it a `#N` id.
- **Correctly severity-rated.** `FAIL` = exploitable / audit-blocking, `WARN` = should-fix
  / needs-review, `PASS` = clean.

## Anatomy of a pod check

Most checks are one line. `check_pods` takes a severity, a domain, a `#N name`, and a
`jq` filter evaluated per pod (over `.items[]`). Return `true` to flag the pod:

```bash
check_pods FAIL "Pod Security" "#7b Dangerous capabilities added" \
  'any(.spec.containers[]?; (.securityContext.capabilities.add // []) | any(. == "SYS_ADMIN" or . == "NET_ADMIN"))'
```

Use `any(.spec.containers[]?; <cond>)` rather than `.spec.containers[]? | <cond>` so a
pod with several matching containers is counted once, not N times.

For checks that aren't per-pod (RBAC bindings, namespaces, cluster-wide objects), add a
small block that ends in a `record PASS|WARN|FAIL "<domain>" "<#N name>" "<detail>"` call —
see the `cluster-admin` and NetworkPolicy blocks for the pattern.

## Submitting

1. Fork and branch.
2. Add your check and run `bash -n k8s-audit.sh` (syntax) plus a run against a kind/minikube
   cluster if you can.
3. If it's a new check, bump the "N of 50" count in `k8s-audit.sh` and `README.md`, and add a
   row to the README table.
4. Open a PR describing the misconfiguration it catches and why it's high-signal.

## Good first issues

New here? The [`good first issue`](https://github.com/k8s-security-pro/k8s-audit/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
label marks small, well-scoped checks — usually with the `jq` filter already sketched in the
issue. Pick one, drop a comment that you're on it, and open a PR.

## License

By contributing, you agree your work is released under the [MIT License](LICENSE).
