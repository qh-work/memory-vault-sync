# Full-client protected storage by platform

The lightweight protocol is independent of an OS, plugin, model or database.
The optional full client additionally needs real local storage, signer and
control-file protection. Protocol portability does **not** imply a protected
installation on every filesystem.

The v0.25 source includes an explicit Windows native storage profile alongside
the existing POSIX implementation. It has been **statically inspected/parsed,
not executed or certified on a Windows machine** in this development pass.
No ACL changes, keys, Vaults, tests, providers or installer processes were run.
The native implementation and synthetic cases are material for independent
validation, not evidence that all combinations below passed.

## Supported protection contracts

| Profile | Required boundary | Deliberate exclusions |
| --- | --- | --- |
| POSIX full client | Existing current-user ownership, private modes, ordinary files, no symlink/hard-link aliases where required, nonblocking file locks | Permission repairs, elevated writes and same-account isolation are not inferred |
| Windows native full client | Local **fixed NTFS** volume with persistent ACLs, current-user private DACLs, native checked handles, nonblocking `LockFileEx` | UNC/SMB or mapped network drives, FAT/exFAT/ReFS/removable drives, reparse points/junctions, device/ADS names, impersonated callers and unsupported complex ACLs fail closed |
| Light protocol/core | Canonical records, relations, transportable evidence and host-provided persistence | No claim that the core alone established native private ACLs or host permission isolation |

Windows cloud-folder placeholders/junctions are intentionally not accepted as
private state. Keep private Vault/control/key directories on ordinary local
NTFS; a separately authorized rclone backend can carry signed exchange files.
This profile is not a universal Windows folder-sharing or ACL repair utility.
Unknown permission conditions return a visible error rather than automatically
changing an existing object to make it pass.

## Native Windows design

`memory_vault_storage.py` loads standard-library `ctypes` bindings only when an
explicit storage operation needs them. Importing it does not inspect accounts,
open files, run commands, create keys, or request elevation. No PowerShell,
`icacls`, registry edit, UAC prompt, policy change or persistence service is used.

New private files/directories receive a security descriptor at **creation**:
the process user owns them; a protected DACL grants that user and LocalSystem.
Directory entries inherit those grants to children, including SQLite sidecars.
Creation is done with explicit `SECURITY_ATTRIBUTES`, not by writing exposed
bytes and subsequently applying `chmod`. Existing objects are checked, not
re-ACL'd. The descriptor construction follows Microsoft's
[security-descriptor conversion API](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw)
and [CreateDirectoryW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).

Private file/directory owners must be the process user; effective allow ACEs
can grant only that user, LocalSystem or local Administrators. Inherit-only
Creator Owner is accepted for a private directory; broad inherit-only read
grants to other identities are rejected so future sidecars do not leak. Simple
deny ACEs cannot create access. Callback/object/conditional ACEs or unknown
flags are rejected rather than partially interpreted. Ancestors and explicitly
selected readable executables can permit other-user reads, but not dangerous
write/delete/ACL/owner changes. A volume root's ordinary create-subdirectory
permission is not treated as permission to replace an already protected child.
ACLs are retrieved from the **opened handle** using
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
and enumerated with [GetAce](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace).

Only normalized local drive paths are accepted. Alternate data streams, device
names, traversal components and any observed reparse point are refused. Every
ancestor is opened and held without delete-sharing during a final open/move;
the final file is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked for a
real disk file, expected directory/file type and a single hard link. Its final
native path must match the selected path. These checks use
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
and [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
The filesystem/ACL capability gate follows
[GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw).

Locks use an explicit one-byte exclusive region with fail-immediately semantics,
not a PID claim, busy loop or a silently ignored POSIX lock. A missing
`file_lock(..., create=False)` target stays missing. Closing the handle releases
its lock; no lock file is erased as a way to break another worker's ownership.
See [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).

Atomic control writes first create a private sibling temporary, write and flush
its bytes, then rename with `MoveFileExW(MOVEFILE_WRITE_THROUGH)` and optional
`MOVEFILE_REPLACE_EXISTING`. No `COPY_ALLOWED` fallback is enabled. Large backup
callers can flush a streaming temporary and use `publish_file` without loading
the whole archive into memory. Source/destination file identities and ACLs are
checked; no-clobber is enforced when replacement was not requested. This is an
NTFS rename/flush design, not a proof against every storage-device power-loss
failure. See [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

## Public local adapter API

```python
require_supported_storage()
validate_path(path)                         # no writes; reject unsafe names/reparse/volume
private_directory(path, create=True)        # create missing private dirs only; no ACL repair
check_private_directory(path)              # read-only equivalent with create=False
open_file(path, flags, private=True)         # checked native fd; no O_TRUNC
check_fd(fd, private=True)                  # inspect actual handle, owner and ACL
atomic_write(path, data, replace=False)      # bounded control bytes; private atomic creation
publish_file(temporary, destination, replace=False)  # flushed private sibling, streaming-safe
with file_lock(lock_path, create=True, busy_code="sync_busy"):
    pass
```

`open_file(..., trusted=True)` allows public reads while refusing other-user
modification; it is suitable for an explicitly pinned rclone executable.
Errors use content-free `StorageError.code`/`retryable`, not raw usernames,
credentials or file contents. POSIX consumers retain their earlier per-module
checks; the Windows branch does not remove them. All signing, Vault/sidecar,
sync state, review journal, staging and updater integration points must choose
the proper private/trusted contract, not merely bypass an `os.name` guard.

The native rclone reader checks available pipe bytes and reads no more than
that amount; this avoids using Windows socket selectors for subprocess pipes.
It has bounded output and cancellation checks. Native I/O may still stall, and
the worker is not a Job Object sandbox for arbitrary descendant executables.
The API distinction is documented by
[PeekNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe).

## Independent validation still needed

`tests/test_v025_storage.py` in the source/review kit provides pure ACL/path
contracts and native synthetic private-file, no-clobber, streaming-publication,
hard-link and lock cases. They have **not** been run. Reviewers should additionally
exercise 32/64-bit calling conventions, non-elevated Windows accounts, two
different OS users, inherited ACL changes, junction/symlink substitution,
inaccessible paths, SQLite WAL/SHM, disk-full and interruption during rename,
provider pipe/output limits and reboot recovery. Run only in a separately
authorized synthetic environment; do not point examples at a real private Vault.

The user, LocalSystem and privileged administrators can still read or change
same-account data. This is not encryption or isolation from an OS compromise.
Memory cannot grant these filesystem privileges, enroll a signer, authorize a
worker, hide activity, change the logging policy or bypass the execution host.
