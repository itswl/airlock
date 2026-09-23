"""Guard for an agent's shell commands, in one of two postures.

Ported from hookstack's hookprobe/guard.py, where it ran in production. The real
boundary is the credential mounted into the container; this guard is defence in
depth that turns an over-eager model's mutation into a clear refusal. It is a
set of regexes over a string the model wrote, so it stops accidents, not an
adversary — ``V=delete; kubectl $V pod x`` gets through, and that is stated
rather than hidden.

  readonly     every investigator. Mutating verbs of the common operations CLIs
               are refused; AWS is inverted (anything that is not a read verb).
  danger-only  worker agents in task mode. Mutation is the job; only the handful
               of actions no credential scope can undo are refused.

Both postures refuse attempts to switch off the egress proxy.
"""

from __future__ import annotations

import re

_SEG = r"[^|;&\n]*"
# An AWS operation that only reads, by the API's own naming convention. The
# lookbehind keeps a path from counting as one: `aws s3 rm s3://b/list-of-keys`
# contains "list" and must still be denied.
#
# Positional parsing was tried first and abandoned — `aws --region eu-west-1 ec2
# describe-volumes` was DENIED because the regex could backtrack into reading
# "eu-west-1" as the service and "ec2" as the operation. Asking "does this
# command read anything at all" needs no parse and has no such seam.
# `update-kubeconfig` is the one exception that is not a read VERB and is still
# a read: it calls DescribeCluster and writes a file on this machine, and can
# mutate nothing in AWS. Denying it was the first false positive this inverted
# rule produced — an investigator that may query EKS could not reach the
# cluster's API at all. Named individually rather than by loosening the verb
# list, because "update" staying denied everywhere else is the point.
_AWS_READ = (
    r"(?<![/:.\w-])(?:describe|get|list|search|head|scan|query|select|lookup|"
    r"estimate|preview|validate|check|test|ls|update-kubeconfig)[a-z0-9-]*\b"
)

_DENY_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            rf"\b(?:kubectl|oc|kubecolor)\b{_SEG}\b(apply|create|delete|edit|patch|replace|scale|autoscale|rollout|run|"
            rf"cordon|uncordon|drain|taint|label|annotate|expose|set|exec|attach|cp|port-forward|proxy|debug)\b"
        ),
        "kubectl mutation or pod entry",
    ),
    (
        re.compile(
            rf"\b(?:helm|helmfile)\b{_SEG}\b(install|upgrade|uninstall|delete|rollback|push|apply|sync|destroy)\b"
        ),
        "helm mutation",
    ),
    (
        re.compile(
            rf"\b(docker|podman|nerdctl|crictl)\b{_SEG}\b(run|exec|rm|rmi|stop|start|kill|restart|unpause|cp|build|push|prune|create)\b"
        ),
        "container runtime mutation",
    ),
    (
        re.compile(rf"\bsystemctl\b{_SEG}\b(start|stop|restart|reload|enable|disable|mask|unmask|kill|isolate)\b"),
        "service state change",
    ),
    (
        re.compile(r"\bservice\s+\S+\s+(start|stop|restart|reload)\b"),
        "service state change",
    ),
    (
        re.compile(rf"\b(terraform|tofu)\b{_SEG}\b(apply|destroy)\b"),
        "infrastructure mutation",
    ),
    (re.compile(r"\bansible-playbook\b"), "configuration management run"),
    (re.compile(r"\b(ssh|scp|sftp|rsync)\b"), "remote shell / file transfer"),
    (re.compile(r"\b(shutdown|reboot|poweroff|halt)\b"), "host power control"),
    (re.compile(rf"\bgit\b{_SEG}\bpush\b"), "git push"),
    # AWS is the one CLI here whose surface is too large and too fast-moving to
    # enumerate mutating verbs for, so this inverts: an operation is denied
    # unless it reads. Every other rule above is "deny these verbs"; this is
    # "deny anything that is not one of these", because a denylist against an
    # API that gains operations weekly is a list that is wrong by next quarter,
    # and being wrong in that direction means an agent holding somebody's keys.
    #
    # `aws s3 ls` and `aws s3api get-object` pass; `aws s3 cp|mv|rm|sync` and
    # every `put-`/`create-`/`delete-`/`terminate-` do not. The read verbs are
    # the AWS API's own naming convention, which is the only reason a list this
    # short can cover it.
    #
    # The lookarounds keep `aws` a COMMAND rather than any occurrence of the
    # three letters. `curl https://docs.aws.amazon.com` was refused as an "aws
    # non-read operation", because `\baws\b` matches the label inside a dotted
    # hostname — measured 2026-09-10, and it is the one documentation host this
    # deployment's WebFetch reaches most. Excluding a dot on either side is the
    # narrow fix: it costs nothing an invocation can use, where widening the
    # preceding class to `[^/:.\w-]` (the shape `_AWS_READ` uses for its verbs)
    # would have let `/usr/local/bin/aws s3 rm` through.
    (
        re.compile(rf"(?<!\.)\baws\b(?!\.)(?![^|;&\n]*{_AWS_READ})"),
        "aws non-read operation",
    ),
)


# The `danger-only` list. Deliberately short, and every entry is something whose
# damage is NOT bounded by the credentials an operator scoped: a wiped
# filesystem, a reformatted disk, a fork bomb, a container escape hatch, an
# estate torn down in one verb. `kubectl delete pod x` is absent on purpose —
# that is the work, and the ServiceAccount is what says which pods.
_DANGER_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # `rm -rf /`, `rm -fr /usr`, and the same with the root reached through a
    # variable that is empty at match time (`rm -rf $D/`, the classic).
    (re.compile(r"\brm\b[^|;&\n]*\s-[a-zA-Z]*[rR][a-zA-Z]*f|\brm\b[^|;&\n]*\s-[a-zA-Z]*f[a-zA-Z]*[rR]"), "rm -rf"),
    (re.compile(r"\b(mkfs|mkfs\.\w+|fdisk|parted|wipefs|shred)\b"), "a filesystem or partition command"),
    (re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/"), "dd onto a device"),
    (re.compile(r":\(\)\s*\{.*\|.*&.*\}\s*;?\s*:"), "a fork bomb"),
    # The container's own escape hatches. There is no socket mounted, so these
    # cannot work today; the rule is what keeps that true if one ever is.
    (re.compile(r"\b(docker|podman|nerdctl|containerd|runc)\b"), "a container runtime"),
    (re.compile(r"\bterraform\b[^|;&\n]*\bdestroy\b|\bpulumi\b[^|;&\n]*\bdestroy\b"), "an infrastructure teardown"),
    # Whole-namespace and whole-cluster deletes: the credential scopes WHICH
    # namespace, never "all of it at once".
    (re.compile(r"\bkubectl\b[^|;&\n]*\bdelete\b[^|;&\n]*(--all\b|\bnamespace\b|\bns\b)"), "a namespace-wide delete"),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"), "a host power command"),
)

# Turning the egress boundary off. Checked under EVERY posture, before the mode
# branch, because this is not about what a runner may change — it is about not
# disabling the thing that records where it went.
#
# the egress proxy bounds the investigator's outbound calls by allowlist,
# and it works by environment (HTTP_PROXY/HTTPS_PROXY/NO_PROXY). That made the
# bypass exactly one shell prefix — `unset HTTPS_PROXY; curl ... -d @/tmp/x` was
# allowed, measured in hookstack on 2026-09-10 — which is ordinary tooling, not a determined
# adversary, and therefore inside the threat this is for.
#
# Honest about what it buys: it moves the bypass from one prefix to writing a
# program. A python one-liner opening its own socket does not read these
# variables and this rule cannot see it. What it also buys, and this is the
# larger half, is that the ATTEMPT lands in the audit as a refusal instead of
# passing silently.
_PROXY_VARS = r"(?:HTTPS?_PROXY|ALL_PROXY|NO_PROXY|https?_proxy|all_proxy|no_proxy)"
_ALWAYS_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"\bunset\b{_SEG}\b{_PROXY_VARS}\b"), "unsetting the egress proxy variables"),
    (re.compile(rf"\benv\b{_SEG}-u\s*{_PROXY_VARS}\b"), "clearing the egress proxy variables"),
    (re.compile(rf"\b{_PROXY_VARS}\s*="), "overriding the egress proxy variables"),
    # The same bypass without touching the environment at all.
    (re.compile(rf"\bcurl\b{_SEG}(--noproxy|-x\s|--proxy[= ])"), "a curl flag that goes around the egress proxy"),
    (re.compile(rf"\bwget\b{_SEG}--no-proxy\b"), "a wget flag that goes around the egress proxy"),
)

READONLY, DANGER_ONLY = "readonly", "danger-only"
MODES = (READONLY, DANGER_ONLY)


def bash_deny_reason(command: str, mode: str = READONLY) -> str | None:
    """Return a human-readable denial reason, or None when the command may run.

    An unknown mode falls back to `readonly`. Failing closed is the only safe
    direction for a typo in an env var that decides whether a runner may write.
    """
    # A shell line-continuation (backslash then newline) joins two physical lines
    # into ONE logical command, but _SEG stops at \n — so `kubectl \<newline>
    # delete pod x` split the verb into a second segment and passed. Models wrap
    # long kubectl/helm lines exactly this way, so this was an accidental hole,
    # not only an adversarial one. Collapse continuations before matching.
    command = re.sub(r"\\\r?\n", " ", command)
    # Before the mode branch: every posture keeps its egress boundary.
    for pattern, label in _ALWAYS_RULES:
        if pattern.search(command):
            return (
                f"egress guard: {label} is blocked. Outbound calls go through the "
                f"allowlisting proxy; a destination it refuses is a destination nobody listed"
            )
    if mode == DANGER_ONLY:
        for pattern, label in _DANGER_RULES:
            if pattern.search(command):
                return (
                    f"danger guard: {label} is blocked. This runner may change what its "
                    f"credentials reach; it may not do something no credential scope can undo"
                )
        return None
    for pattern, label in _DENY_RULES:
        if pattern.search(command):
            return f"read-only guard: {label} is blocked; this runner may only observe, never change"
    return None
