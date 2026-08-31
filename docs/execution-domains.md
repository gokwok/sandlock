# Managed session execution domains

Hosted Rust runtimes may call `Sandbox::enable_session_domain()` before
`create`/`popen`. This is an explicit runtime ownership contract, not a serialized
policy field. It requires the notification supervisor and does not change
`no_supervisor` or the default interactive shell lifecycle.

The trusted launch path creates a private Linux session before confinement.
The workload may create process groups with `setpgid`, but cannot call `setsid`
or create/join namespaces. The session is not an Agent conversation checkpoint.
The owner retains the direct child as the session identity anchor until every
live session member has exited; it must not reap that child early.

`ExecutionDomain` controls the complete session, including descendants that
change PGID or outlive their parent. Signals use captured pidfds, not numeric
PID-only kills. A domain descriptor is private live runtime metadata, not a
durable policy or a credential. Reopening requires the original anchor identity.
If the anchor disappeared or was reused, cleanup is indeterminate: callers must
retain their writer/storage fence rather than infer success from an empty scan.

Pause closes a bounded notification gate, drains operations already admitted
(including fork birth tracking and deferred handlers), and confirms that every
task in the session is held in a ptrace stop or a valid, received notification.
The latter requires `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`. Installation
probes actual thread-pidfd support and prefers this flag when the complete
kernel-assisted freeze is available. If a prerequisite is unsupported, managed
execution automatically uses ordinary notifications instead: process pidfds
request group-stop, every live thread must settle, and a pinned ptrace owner
confirms and holds every thread's stop. An open proc identity prevents a reused
numeric TID from being mistaken for the captured task. No thread-pidfd or
notification-wait assumption is used by this compatibility path.

The listener handshake carries the actual installed wait mode; it is never
inferred from a kernel version or a separate Host environment. The private
bootstrap protocol is version 2 and requires a matching bootstrap executable.
Only unsupported-operation errors permit capability fallback; permission or
filter installation failures remain errors. The filesystem policy and
notification supervisor are never disabled. New notifications remain queued
until resume; canceled IDs are discarded and restarted calls are revalidated
and dispatched normally, never blindly continued. Freeze
failure resumes the execution or reports cleanup failure. A process in an
uninterruptible wait without that notification proof is not accepted as a
completed filesystem freeze. In particular a vfork parent waiting for a parked
child can cause a bounded freeze failure; callers must report failure and retry
after that native operation completes, never snapshot through it. SIGCONT
cannot release the ptrace stops during a successful freeze.

Managed creation tracks thread clones as well as process clones. `clone3`
returns `ENOSYS` in this mode so libraries fall back to register-argument
`clone`; this avoids making lifecycle membership depend on mutable user-memory
flags. `CLONE_UNTRACED` and namespace creation remain denied.

Wait observes the direct child's exit without reaping, terminates and verifies
the remaining session, then reaps the child and retires the domain. Branch
detach, CPU throttling, cancellation, and failure cleanup use the same domain.
PTY bytes and foreground-job semantics remain independent of domain control.

No root, cgroup, new namespace, or global daemon is required by this contract.
The deployment must permit ordinary process pidfds, seccomp user notification
and ptrace birth tracking/freezing. Thread pidfds and killable notification
waits are optional optimizations. Missing base facilities fail closed. These
requirements do not lower the normal protection-policy minimum.

The existing FFI/CLI/Python/Go policy schema is unchanged. This initial hosted
runtime contract is a Rust API; deserializing or cloning a policy does not
transfer a running domain or a cleanup proof.
