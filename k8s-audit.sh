#!/usr/bin/env bash
#
# k8s-audit — a fast, dependency-light Kubernetes security audit.
#
# Runs a set of high-signal security checks against your current cluster using
# only kubectl + jq, grouped by the 9 domains of the k8s-security.pro 50-point
# checklist. If kube-bench / Trivy / kubescape are installed, it points you to
# them for deeper CIS/NSA coverage.
#
# Nothing is sent anywhere. Read-only: it never mutates your cluster.
#
#   Usage:  ./k8s-audit.sh [-n NAMESPACE] [--json]
#
# Full 50-point checklist, remediation YAML, Helm & Kustomize:
#   https://k8s-security.pro
#
# MIT License — (c) k8s-security.pro
set -euo pipefail

NS_FILTER=""          # empty = all namespaces
JSON=false
PASS=0; WARN=0; FAIL=0
declare -a FINDINGS    # "SEVERITY|DOMAIN|CHECK|DETAIL"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NS_FILTER="$2"; shift 2 ;;
    --json) JSON=true; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found (brew install jq)" >&2; exit 1; }

if [[ -n "$NS_FILTER" ]]; then NS_ARGS=(-n "$NS_FILTER"); else NS_ARGS=(--all-namespaces); fi

# pull all pods once
PODS_JSON="$(kubectl get pods "${NS_ARGS[@]}" -o json 2>/dev/null || echo '{"items":[]}')"

record() { FINDINGS+=("$1|$2|$3|$4"); case "$1" in PASS) ((PASS++));; WARN) ((WARN++));; FAIL) ((FAIL++));; esac; }

# helper: count pods matching a jq filter over .items[]
count_pods() { echo "$PODS_JSON" | jq "[.items[] | select($1)] | length"; }
list_pods()  { echo "$PODS_JSON" | jq -r "[.items[] | select($1) | .metadata.namespace + \"/\" + .metadata.name] | .[0:8] | .[]"; }

check_pods() { # severity domain "#N check" jq_filter
  local sev="$1" dom="$2" name="$3" filt="$4"
  local c; c="$(count_pods "$filt")"
  if [[ "$c" == "0" ]]; then record PASS "$dom" "$name" "no matching workloads"
  else record "$sev" "$dom" "$name" "$c workload(s): $(list_pods "$filt" | paste -sd, -)"; fi
}

# ── Pod Security (checklist domain I) ─────────────────────────────────────────
check_pods FAIL "Pod Security" "#2 Privileged containers" \
  '.spec.containers[]?.securityContext?.privileged == true'
check_pods FAIL "Pod Security" "#3 allowPrivilegeEscalation not disabled" \
  '(.spec.containers[]? | (.securityContext.allowPrivilegeEscalation // true)) == true'
check_pods WARN "Pod Security" "#4 Running as root (runAsNonRoot unset)" \
  '((.spec.securityContext.runAsNonRoot // false) == false) and (all(.spec.containers[]?; (.securityContext.runAsNonRoot // false) == false))'
check_pods FAIL "Pod Security" "#5 hostNetwork / hostPID / hostIPC" \
  '(.spec.hostNetwork == true) or (.spec.hostPID == true) or (.spec.hostIPC == true)'
check_pods WARN "Pod Security" "#6 SA token auto-mounted" \
  '(.spec.automountServiceAccountToken // true) == true'
check_pods WARN "Pod Security" "#7 Capabilities not dropped (ALL)" \
  '.spec.containers[]? | ((.securityContext.capabilities.drop // []) | index("ALL")) == null'

# ── Supply Chain (domain V) ───────────────────────────────────────────────────
check_pods WARN "Supply Chain" "#28 Images using :latest or untagged" \
  '.spec.containers[]?.image | (test(":latest$")) or (test(":") | not)'

# ── Resource Management (domain IV) ──────────────────────────────────────────
check_pods WARN "Cluster Hardening" "#22 Containers without resource limits" \
  '.spec.containers[]? | (.resources.limits == null)'

# ── Cluster hygiene ──────────────────────────────────────────────────────────
DEFAULT_WORKLOADS="$(kubectl get pods -n default --no-headers 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$DEFAULT_WORKLOADS" == "0" ]]; then record PASS "Cluster Hardening" "#20 Workloads in default namespace" "default namespace is empty"
else record WARN "Cluster Hardening" "#20 Workloads in default namespace" "$DEFAULT_WORKLOADS pod(s) in 'default'"; fi

# ── Network (domain II): namespaces with no NetworkPolicy ────────────────────
NP_MISSING=""
while read -r ns; do
  [[ -z "$ns" || "$ns" =~ ^(kube-system|kube-public|kube-node-lease)$ ]] && continue
  local_np="$(kubectl get netpol -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$local_np" == "0" ]] && NP_MISSING+="$ns "
done < <(kubectl get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n')
if [[ -z "$NP_MISSING" ]]; then record PASS "Network" "#8 Namespaces without a NetworkPolicy" "all namespaces have at least one"
else record FAIL "Network" "#8 Namespaces without a NetworkPolicy" "no default-deny in: ${NP_MISSING% }"; fi

# ── RBAC (domain III): cluster-admin bindings ────────────────────────────────
ADMIN_BINDINGS="$(kubectl get clusterrolebindings -o json 2>/dev/null \
  | jq -r '[.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name] | length' 2>/dev/null || echo 0)"
if [[ "$ADMIN_BINDINGS" -le 1 ]]; then record PASS "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS binding(s)"
else record WARN "RBAC" "#14 cluster-admin bindings" "$ADMIN_BINDINGS bindings grant cluster-admin — review each"; fi

# ── Output ───────────────────────────────────────────────────────────────────
if $JSON; then
  printf '{'
  printf '"pass":%d,"warn":%d,"fail":%d,"findings":[' "$PASS" "$WARN" "$FAIL"
  for i in "${!FINDINGS[@]}"; do
    IFS='|' read -r sev dom name detail <<<"${FINDINGS[$i]}"
    [[ $i -gt 0 ]] && printf ','
    printf '{"severity":"%s","domain":"%s","check":"%s","detail":%s}' \
      "$sev" "$dom" "$name" "$(jq -Rn --arg d "$detail" '$d')"
  done
  printf ']}\n'
  exit 0
fi

c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
echo
echo "  k8s-audit · $(kubectl config current-context 2>/dev/null || echo cluster)"
echo "  ${c_dim}high-signal checks mapped to the k8s-security.pro 50-point checklist${c_rst}"
echo
last_dom=""
for f in "${FINDINGS[@]}"; do
  IFS='|' read -r sev dom name detail <<<"$f"
  [[ "$dom" != "$last_dom" ]] && { echo "  ── $dom"; last_dom="$dom"; }
  case "$sev" in
    PASS) icon="${c_grn}✓${c_rst}";;
    WARN) icon="${c_yel}![${c_rst}";;
    FAIL) icon="${c_red}✗${c_rst}";;
  esac
  printf "     %s %-42s %s%s%s\n" "$icon" "$name" "$c_dim" "$detail" "$c_rst"
done
echo
echo "  ${c_grn}${PASS} pass${c_rst}   ${c_yel}${WARN} warn${c_rst}   ${c_red}${FAIL} fail${c_rst}"
echo
echo "  ${c_dim}This covers ~12 of 50 checks. For the full 50-point audit, remediation${c_rst}"
echo "  ${c_dim}YAML, Helm charts, Kustomize overlays and CIS/SOC2 mappings:${c_rst}"
echo "  → https://k8s-security.pro"
echo
if command -v kubescape >/dev/null 2>&1 || command -v trivy >/dev/null 2>&1 || command -v kube-bench >/dev/null 2>&1; then
  echo "  ${c_dim}Deeper CIS/NSA scans (detected on PATH):${c_rst}"
  command -v kubescape >/dev/null 2>&1 && echo "     kubescape scan framework nsa"
  command -v trivy     >/dev/null 2>&1 && echo "     trivy k8s --report summary cluster"
  command -v kube-bench>/dev/null 2>&1 && echo "     kube-bench run --targets master,node"
  echo
fi
[[ "$FAIL" -gt 0 ]] && exit 1 || exit 0
