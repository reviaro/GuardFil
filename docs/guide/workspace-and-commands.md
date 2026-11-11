# Workspace access and command rules

The executor mounts a policy-controlled filesystem view at `/workspace`.
The original host directory is not mounted into the agent. File reads and
writes go through the same policy service whether they come from a native
file tool, a shell command, or a Python agent.

## Host setup and existing policies

The Linux host needs `/dev/fuse`, `fusermount3`, and kernel support for
`openat2`. A host administrator must enable `user_allow_other` in
`/etc/fuse.conf` (`echo user_allow_other | sudo tee -a /etc/fuse.conf`).
This lets Docker's daemon bind the user's FUSE mount. The setting is
host-wide: any local user may then create FUSE mounts that other users can
access. `guardfil-local.sh check` verifies the setup.
GuardFil keeps the view beneath a private directory and does not add
capabilities or device access to agent containers. It refuses to start if
the view cannot be mounted; there is no raw-directory fallback.

Run `guardfil-local.sh up` after updating to extract the new
`guardfil-workspace` helper. Existing policies need an explicit read grant;
allowing a read tool alone no longer grants filesystem access:

```yaml
- id: allow-workspace-reads
  effect: allow
  match:
    principals: [codex-agent]
    operations: [filesystem.read]
    resources: [{kind: path, value: /workspace/**}]
```

The starter policy includes that grant. Add narrower Block rules in the
Policy tab for files the agent must not read. Blocks take precedence over
grants. Keep runtime binaries, GuardFil configuration and
session state outside the selected workspace: additional mounts that
overlap its original directory are rejected.

Multiple sessions can use the same workspace, overlapping parent/child
directories or separate worktrees. Helpers coordinate namespace changes and
IO to the same backing object. Locks are released after each operation or
when a helper exits. An operation waiting for approval can delay another
session's conflicting work.

## Filesystem behavior

Paths in policy use the agent's `/workspace` namespace. The filesystem checks
the opened backing object as well as its requested path. Symlinks that stay
inside the workspace can work; access to their targets must also be allowed.
Absolute symlinks into the selected source or `/workspace` are translated
into links within the view. Hard links work when every alias is inside the
selected source and permitted by policy. A link with an unaccounted-for
alias outside the workspace is refused.

Nested ordinary-storage mounts and bind aliases are supported, with checks
against all visible names of an object. Supported filesystem types are
ext2/3/4, XFS, Btrfs, tmpfs, overlayfs, NFS, CIFS/SMB2, F2FS and ramfs;
this is not a claim of testing every implementation. Kernel API filesystems
such as procfs/sysfs, device nodes, other FUSE sources, escaping symlinks,
extended attributes and shared memory mapping are unsupported. Normal files,
directories, rename, append, truncate, permissions and timestamps work.

A denied read hides the entry from directory listings and prevents operations
that need to look it up, including writes to an existing unreadable file. Moving a directory
requires access to its descendants, so renaming a parent cannot move a
protected file outside its rule. Large directory moves are scanned in bounded
batches without a fixed entry-count limit. Hard-link and bind-alias scans can
be expensive; large-workspace performance has not been characterized.
Open file handles, including unlinked files, are checked again on each read and write;
policy changes and decision-service failure therefore apply to later IO.
Data already read by an agent cannot be recalled.

Named pipes and Unix sockets work within one view. Their endpoints are
isolated from the host backing directory and other sessions' views. Access
requires both read and write permission. Existing IPC connections remain
usable until closed; changing policy blocks new access, not individual bytes
on an already-open channel.

For an Ask me file prompt, **Allow for session** remembers the exact path and
read or write operation. It covers subsequent lookup/open/IO checks without
another prompt. **Allow once** permits just the held request. New files,
aliases or operations may still ask. **Clear file approvals** revokes a
session's grants; policy, content-rule or catalog changes and session end
also invalidate them. A grant never overrides a Block. The cap is 4,096
path/operation grants per session. The filesystem does not transform contents.
Supported native read/search hooks defer workspace access checks to the
mediated filesystem; their tool-level rules still apply.

These controls apply inside GuardFil's executor. Host applications still
access the original directory normally. Review agent-written scripts before
running them on the host.

## Local-only data

In Policy, enter paths under **Local-only files**, one per line, and save.
For example, `/workspace/private/**` marks a folder and its contents. The
headless equivalent is a top-level policy field:

```yaml
local_only_paths:
  - /workspace/private/**
```

This classification applies to every agent. It does not grant read or write
permission; ordinary file rules still decide access. Once a session reads a
classified file, GuardFil keeps that session local for the rest of its life:

- Host brokers refuse further provider requests, including token counting
  and retries. External tool and gateway calls are blocked too.
- Local computation can continue, but workspace outputs must stay within
  local-only locations. Copying or encoding data into a public file, moving
  it there or creating a public hard link is blocked.
- Another session reading the private output becomes local-only too.
  Clearing approvals or removing a path from the list does not reset an
  already-private session. A new session can use the cloud until it accesses
  private data.

Cloud-driven agents normally stop at their next model turn. GuardFil does
not automatically switch them to a local model. This feature prevents future
disclosure; it cannot recall bytes already sent to a provider.
Filesystem lookups and directory listings also count as reads, so examining
a classified entry can engage protection before its file contents are read.

The host launcher binds each session to its storage mappings. Once registered,
these mappings preserve classification across parent/child workspace roots
and bind aliases; they survive session deletion and service restart in
`state/workspace-privacy.json`. Changing the privacy list conservatively keeps
already-reading sessions local. Registering a new overlapping workspace can
do the same, because it can introduce a protected name for data already read.
Mappings are limited to 256 per view and 1,024 distinct views per service.
Configure privacy against the intended workspace before accessing its data.

Keep the host source's mount topology stable during a run; restart affected
runs after host mount changes. The host and owner socket remain trusted.
Privacy enforcement requires the shipped session-bound launchers and brokers;
a custom or standalone broker without that binding is outside this guarantee.
The owner socket, session identifier and real provider credentials stay on
the host. Missing sessions or an unreachable decision service block cloud use.

## Exact commands and prefixes

In the Policy tab, choose **Shell command (exact)** or **Shell command
prefix**, enter a command, and choose Allow, Block, Monitor or Ask me.

| Rule | Matches | Does not match |
| --- | --- | --- |
| Exact `git status` | `git status` | `git status --short` |
| Prefix `git status` | `git status`, `git status --short` | `git status-other`, `git reset` |
| Prefix `rm` | `rm notes`, `rm -rf build` | `rmdir build` |

Prefixes match whole arguments. Quote arguments containing spaces. Command
names are literal: `git` and `/usr/bin/git` are different selectors.

Once an agent has any command rules, every simple command in a request must
match an Allow, Monitor or Ask me rule. Existing all-shell Block and Ask me
rules continue to apply. To let `git status` run without a prompt under the
starter policy, replace its all-shell Ask me rule with the narrower command
rules you want. A missing command grant blocks the request.

GuardFil checks every stage of a static chain, pipeline or nested supported
shell before allowing any of it to execute. `git status; rm notes` requires
both commands to be permitted. Dynamic expansions, assignments, loops,
functions, background execution and other unresolved syntax are refused
when command rules apply. Shell startup uses a home and executable search
path outside writable workspace and temporary directories.

The policy representation is `shell.execute` with a `command` selector:

```yaml
- id: inspect-git
  effect: allow
  match:
    principals: [codex-agent]
    operations: [shell.execute]
    resources: [{kind: command, value: '["git","status"]/**'}]
- id: never-remove
  effect: deny
  match:
    principals: [codex-agent]
    operations: [shell.execute]
    resources: [{kind: command, value: '["rm"]/**'}]
```

Omit `/**` for an exact argument list. JSON arrays must use their compact
canonical form. `*` explicitly matches any resolved command. Principals
without command rules retain the existing all-shell behavior.

Command rules authorize the submitted program and arguments. They do not
analyze what an allowed interpreter, build tool, script or Git hook will do.
Granting those programs can authorize substantial behavior; filesystem and
network boundaries still constrain their effects. Custom Python tool
implementations must submit shell requests to the approval socket to use
command rules. Their workspace IO is mediated regardless.

## Without the web UI

Use the same policy YAML and approval sockets. Filesystem requests are
`{"kind":"file_read","paths":["/workspace/note"]}` and the existing
`file_write` change batches. Shell requests retain the existing
`{"kind":"shell","command":["bash","-c","git status"],"cwd":"/workspace"}`
shape. Owner HTTP APIs support session grants with `scope: "session"` on an
approval response, `GET /v1/file-grants` for summaries and
`DELETE /sessions/{session}/file-grants` for revocation. Agent requests cannot
choose their session identity or grant scope. An absent owner cannot release an Ask me request. A decision-service
failure denies filesystem access instead of granting it.
