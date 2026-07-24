#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "shellbridge-helper currently supports Linux x86_64 only"
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif

#define DENY_SYSCALL(number) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

struct inode_slot {
  dev_t device;
  ino_t inode;
  unsigned char used;
};

struct inode_set {
  struct inode_slot *slots;
  size_t capacity;
  size_t size;
};

static const struct sock_filter network_filter[] = {
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
  BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT, 0, 1),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  DENY_SYSCALL(__NR_socket),
  DENY_SYSCALL(__NR_connect),
  DENY_SYSCALL(__NR_accept),
  DENY_SYSCALL(__NR_accept4),
  DENY_SYSCALL(__NR_bind),
  DENY_SYSCALL(__NR_listen),
  DENY_SYSCALL(__NR_sendto),
  DENY_SYSCALL(__NR_sendmsg),
  DENY_SYSCALL(__NR_sendmmsg),
  DENY_SYSCALL(__NR_recvfrom),
  DENY_SYSCALL(__NR_recvmsg),
  DENY_SYSCALL(__NR_recvmmsg),
  DENY_SYSCALL(__NR_shutdown),
  DENY_SYSCALL(__NR_mount),
  DENY_SYSCALL(__NR_umount2),
  DENY_SYSCALL(__NR_pivot_root),
  DENY_SYSCALL(__NR_chroot),
  DENY_SYSCALL(__NR_ptrace),
  DENY_SYSCALL(__NR_bpf),
  DENY_SYSCALL(__NR_keyctl),
  DENY_SYSCALL(__NR_add_key),
  DENY_SYSCALL(__NR_request_key),
  DENY_SYSCALL(__NR_open_by_handle_at),
  DENY_SYSCALL(__NR_name_to_handle_at),
  DENY_SYSCALL(__NR_init_module),
  DENY_SYSCALL(__NR_finit_module),
  DENY_SYSCALL(__NR_delete_module),
  DENY_SYSCALL(__NR_reboot),
  DENY_SYSCALL(__NR_kexec_load),
  DENY_SYSCALL(__NR_swapon),
  DENY_SYSCALL(__NR_swapoff),
  DENY_SYSCALL(__NR_setns),
  DENY_SYSCALL(__NR_unshare),
#ifdef __NR_io_uring_setup
  DENY_SYSCALL(__NR_io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
  DENY_SYSCALL(__NR_io_uring_enter),
#endif
#ifdef __NR_io_uring_register
  DENY_SYSCALL(__NR_io_uring_register),
#endif
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static void fail(const char *code) {
  dprintf(STDERR_FILENO, "shellbridge_helper:%s\n", code);
  _exit(1);
}

static unsigned long long parse_unsigned(const char *raw, unsigned long long maximum, const char *code) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || value > maximum) fail(code);
  return value;
}

static int openat2_beneath(int directory_fd, const char *relative_path, uint64_t flags, uint64_t resolve) {
  struct open_how how = { .flags = flags, .resolve = resolve };
  return (int)syscall(SYS_openat2, directory_fd, relative_path, &how, sizeof(how));
}

static uint64_t inode_hash(dev_t device, ino_t inode) {
  uint64_t value = (uint64_t)device * 0x9e3779b97f4a7c15ULL ^ (uint64_t)inode;
  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27;
  return value ^ (value >> 31);
}

static void inode_set_grow(struct inode_set *set) {
  size_t next_capacity = set->capacity == 0 ? 1024 : set->capacity * 2;
  if (next_capacity < set->capacity) fail("inode_set_failed");
  struct inode_slot *next = calloc(next_capacity, sizeof(*next));
  if (next == NULL) fail("inode_set_failed");
  for (size_t index = 0; index < set->capacity; index += 1) {
    if (!set->slots[index].used) continue;
    size_t target = (size_t)(inode_hash(set->slots[index].device, set->slots[index].inode) & (next_capacity - 1));
    while (next[target].used) target = (target + 1) & (next_capacity - 1);
    next[target] = set->slots[index];
  }
  free(set->slots);
  set->slots = next;
  set->capacity = next_capacity;
}

static int inode_set_contains(const struct inode_set *set, dev_t device, ino_t inode) {
  if (set->capacity == 0) return 0;
  size_t index = (size_t)(inode_hash(device, inode) & (set->capacity - 1));
  while (set->slots[index].used) {
    if (set->slots[index].device == device && set->slots[index].inode == inode) return 1;
    index = (index + 1) & (set->capacity - 1);
  }
  return 0;
}

static void inode_set_add(struct inode_set *set, dev_t device, ino_t inode) {
  if (set->capacity == 0 || (set->size + 1) * 10 >= set->capacity * 7) inode_set_grow(set);
  if (inode_set_contains(set, device, inode)) return;
  size_t index = (size_t)(inode_hash(device, inode) & (set->capacity - 1));
  while (set->slots[index].used) index = (index + 1) & (set->capacity - 1);
  set->slots[index] = (struct inode_slot){ .device = device, .inode = inode, .used = 1 };
  set->size += 1;
}

static void collect_inodes(int descriptor, struct inode_set *collected, struct inode_set *visited) {
  struct stat metadata;
  if (fstat(descriptor, &metadata) != 0) fail("runtime_validation_failed");
  inode_set_add(collected, metadata.st_dev, metadata.st_ino);
  if (!S_ISDIR(metadata.st_mode) || inode_set_contains(visited, metadata.st_dev, metadata.st_ino)) return;
  inode_set_add(visited, metadata.st_dev, metadata.st_ino);
  DIR *directory = fdopendir(dup(descriptor));
  if (directory == NULL) fail("runtime_validation_failed");
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    if (fstatat(descriptor, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
      closedir(directory);
      fail("runtime_validation_failed");
    }
    inode_set_add(collected, metadata.st_dev, metadata.st_ino);
    if (S_ISDIR(metadata.st_mode)) {
      int child = openat(descriptor, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (child < 0) {
        closedir(directory);
        fail("runtime_validation_failed");
      }
      collect_inodes(child, collected, visited);
      close(child);
    }
  }
  closedir(directory);
}

static void verify_disjoint(int descriptor, const struct inode_set *blocked, struct inode_set *visited) {
  struct stat metadata;
  if (fstat(descriptor, &metadata) != 0 || inode_set_contains(blocked, metadata.st_dev, metadata.st_ino)) {
    fail("runtime_contains_blocked_object");
  }
  if (!S_ISDIR(metadata.st_mode) || inode_set_contains(visited, metadata.st_dev, metadata.st_ino)) return;
  inode_set_add(visited, metadata.st_dev, metadata.st_ino);
  DIR *directory = fdopendir(dup(descriptor));
  if (directory == NULL) fail("runtime_validation_failed");
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    if (fstatat(descriptor, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
      closedir(directory);
      fail("runtime_validation_failed");
    }
    if (inode_set_contains(blocked, metadata.st_dev, metadata.st_ino)) {
      closedir(directory);
      fail("runtime_contains_blocked_object");
    }
    if (S_ISDIR(metadata.st_mode)) {
      int child = openat(descriptor, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (child < 0) {
        closedir(directory);
        fail("runtime_validation_failed");
      }
      verify_disjoint(child, blocked, visited);
      close(child);
    }
  }
  closedir(directory);
}

static void validate_disjoint_fds(const char *runtime_raw, const char *blocked_raw) {
  size_t runtime_count = (size_t)parse_unsigned(runtime_raw, 64, "invalid_helper_request");
  size_t blocked_count = (size_t)parse_unsigned(blocked_raw, 256, "invalid_helper_request");
  if (runtime_count == 0 || blocked_count == 0) fail("invalid_helper_request");
  struct inode_set blocked = {0};
  struct inode_set blocked_visited = {0};
  for (size_t index = 0; index < blocked_count; index += 1) {
    collect_inodes(3 + (int)runtime_count + (int)index, &blocked, &blocked_visited);
  }
  struct inode_set runtime_visited = {0};
  for (size_t index = 0; index < runtime_count; index += 1) {
    verify_disjoint(3 + (int)index, &blocked, &runtime_visited);
  }
  free(blocked.slots);
  free(blocked_visited.slots);
  free(runtime_visited.slots);
}

static void secure_read(const char *root, const char *relative_path, const char *raw_max_bytes) {
  if (relative_path[0] == '\0' || relative_path[0] == '/') fail("invalid_relative_path");
  size_t max_bytes = (size_t)parse_unsigned(raw_max_bytes, 16 * 1024 * 1024, "invalid_max_bytes");
  if (max_bytes == 0) fail("invalid_max_bytes");
  int root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd < 0) fail("registered_root_unavailable");

  int file_fd = openat2_beneath(
    root_fd,
    relative_path,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
  );
  if (file_fd < 0) fail("config_target_unavailable");
  close(root_fd);

  struct stat metadata;
  if (fstat(file_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)) fail("config_target_not_regular");
  if (metadata.st_size < 0 || (unsigned long long)metadata.st_size > max_bytes) fail("config_too_large");

  char buffer[8192];
  size_t total = 0;
  for (;;) {
    ssize_t count = read(file_fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) continue;
      fail("config_read_failed");
    }
    if (count == 0) break;
    if (total + (size_t)count > max_bytes) fail("config_too_large");
    size_t offset = 0;
    while (offset < (size_t)count) {
      ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)count - offset);
      if (written < 0) {
        if (errno == EINTR) continue;
        fail("config_output_failed");
      }
      offset += (size_t)written;
    }
    total += (size_t)count;
  }
  close(file_fd);
}

static int validate_directory(int root_fd, int directory_fd, const char *prefix, dev_t root_device) {
  DIR *directory = fdopendir(dup(directory_fd));
  if (directory == NULL) return -1;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    char relative[PATH_MAX];
    int length = prefix[0] == '\0'
      ? snprintf(relative, sizeof(relative), "%s", entry->d_name)
      : snprintf(relative, sizeof(relative), "%s/%s", prefix, entry->d_name);
    if (length < 0 || (size_t)length >= sizeof(relative)) {
      closedir(directory);
      return -1;
    }
    struct stat metadata;
    if (fstatat(directory_fd, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
      closedir(directory);
      return -1;
    }
    if (metadata.st_dev != root_device) {
      closedir(directory);
      return -1;
    }
    if (S_ISLNK(metadata.st_mode) || S_ISSOCK(metadata.st_mode) || S_ISFIFO(metadata.st_mode)
        || S_ISCHR(metadata.st_mode) || S_ISBLK(metadata.st_mode)) continue;
    int pinned_fd = openat2_beneath(
      root_fd,
      relative,
      O_PATH | O_CLOEXEC,
      RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
    );
    if (pinned_fd < 0 || fstat(pinned_fd, &metadata) != 0
        || metadata.st_dev != root_device) {
      if (pinned_fd >= 0) close(pinned_fd);
      closedir(directory);
      return -1;
    }
    close(pinned_fd);
    if (S_ISDIR(metadata.st_mode)) {
      int child_fd = openat2_beneath(
        root_fd,
        relative,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV
      );
      if (child_fd < 0 || validate_directory(root_fd, child_fd, relative, root_device) != 0) {
        if (child_fd >= 0) close(child_fd);
        closedir(directory);
        return -1;
      }
      close(child_fd);
    }
  }
  closedir(directory);
  return 0;
}

static void validate_tree_fd(int root_fd, int parent_fd, int filesystem_fd, const char *root_name) {
  if (fcntl(root_fd, F_GETFD) < 0 || fcntl(parent_fd, F_GETFD) < 0 || fcntl(filesystem_fd, F_GETFD) < 0
      || root_name[0] == '\0' || strchr(root_name, '/') != NULL
      || strcmp(root_name, ".") == 0 || strcmp(root_name, "..") == 0) {
    fail("sandbox_root_unavailable");
  }
  struct stat metadata;
  if (fstat(root_fd, &metadata) != 0 || metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0) {
    fail("sandbox_root_not_trusted");
  }
  int reopened = openat2_beneath(
    parent_fd,
    root_name,
    O_PATH | O_DIRECTORY | O_CLOEXEC,
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
  );
  struct stat reopened_metadata;
  if (reopened < 0 || fstat(reopened, &reopened_metadata) != 0
      || metadata.st_dev != reopened_metadata.st_dev || metadata.st_ino != reopened_metadata.st_ino) {
    if (reopened >= 0) close(reopened);
    fail("sandbox_root_changed");
  }
  struct statx root_mount = {0};
  struct statx parent_mount = {0};
  struct statx filesystem_mount = {0};
  if (syscall(SYS_statx, root_fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_MNT_ID, &root_mount) != 0
      || syscall(SYS_statx, parent_fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_MNT_ID, &parent_mount) != 0
      || syscall(SYS_statx, filesystem_fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_MNT_ID, &filesystem_mount) != 0
      || (root_mount.stx_mask & STATX_MNT_ID) == 0 || (parent_mount.stx_mask & STATX_MNT_ID) == 0
      || (filesystem_mount.stx_mask & STATX_MNT_ID) == 0
      || root_mount.stx_mnt_id != parent_mount.stx_mnt_id
      || root_mount.stx_mnt_id != filesystem_mount.stx_mnt_id) {
    close(reopened);
    fail("sandbox_root_is_mountpoint");
  }
  close(reopened);
  if (validate_directory(root_fd, root_fd, "", metadata.st_dev) != 0) fail("sandbox_root_contains_unsafe_resource");
}

static void write_seccomp(const char *target) {
  int descriptor = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (descriptor < 0) fail("seccomp_output_failed");
  const char *bytes = (const char *)network_filter;
  size_t total = sizeof(network_filter);
  size_t offset = 0;
  while (offset < total) {
    ssize_t count = write(descriptor, bytes + offset, total - offset);
    if (count < 0) {
      if (errno == EINTR) continue;
      fail("seccomp_output_failed");
    }
    offset += (size_t)count;
  }
  if (fsync(descriptor) != 0 || close(descriptor) != 0) fail("seccomp_output_failed");
}

static void set_limit(int resource, rlim_t value) {
  struct rlimit limit = { .rlim_cur = value, .rlim_max = value };
  if (setrlimit(resource, &limit) != 0) fail("resource_limit_failed");
}

static void apply_limits(
  const char *cpu,
  const char *memory,
  const char *processes,
  const char *file_size,
  const char *files
) {
  set_limit(RLIMIT_CPU, (rlim_t)parse_unsigned(cpu, 3600, "invalid_resource_limit"));
  set_limit(RLIMIT_AS, (rlim_t)parse_unsigned(memory, 64ULL * 1024 * 1024 * 1024, "invalid_resource_limit"));
  set_limit(RLIMIT_NPROC, (rlim_t)parse_unsigned(processes, 4096, "invalid_resource_limit"));
  set_limit(RLIMIT_FSIZE, (rlim_t)parse_unsigned(file_size, 1024ULL * 1024 * 1024, "invalid_resource_limit"));
  set_limit(RLIMIT_NOFILE, (rlim_t)parse_unsigned(files, 4096, "invalid_resource_limit"));
  set_limit(RLIMIT_CORE, 0);
}

static void install_seccomp(void) {
  struct sock_fprog program = {
    .len = (unsigned short)(sizeof(network_filter) / sizeof(network_filter[0])),
    .filter = (struct sock_filter *)network_filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail("no_new_privileges_failed");
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) fail("seccomp_install_failed");
}

static void verify_no_capabilities(void) {
  struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
  struct __user_cap_data_struct data[2] = {0};
  if (syscall(SYS_capget, &header, data) != 0) fail("capability_check_failed");
  for (size_t index = 0; index < 2; index += 1) {
    if (data[index].effective != 0 || data[index].permitted != 0 || data[index].inheritable != 0) {
      fail("capabilities_not_empty");
    }
  }
}

static unsigned long long namespace_inode(const char *path) {
  struct stat metadata;
  if (stat(path, &metadata) != 0) fail("namespace_check_failed");
  return (unsigned long long)metadata.st_ino;
}

static void sandbox_init(int argc, char **argv) {
  if (argc != 12) fail("invalid_helper_request");
  uid_t expected_uid = (uid_t)parse_unsigned(argv[2], UINT_MAX, "invalid_observer_identity");
  gid_t expected_gid = (gid_t)parse_unsigned(argv[3], UINT_MAX, "invalid_observer_identity");
  if (expected_uid == 0 || expected_gid == 0 || getuid() != expected_uid || getgid() != expected_gid) {
    fail("observer_identity_failed");
  }
  unsigned long long host_net = parse_unsigned(argv[4], ULLONG_MAX, "invalid_namespace_identity");
  unsigned long long host_pid = parse_unsigned(argv[5], ULLONG_MAX, "invalid_namespace_identity");
  if (namespace_inode("/proc/self/ns/net") == host_net || namespace_inode("/proc/self/ns/pid") == host_pid) {
    fail("namespace_isolation_failed");
  }
  if (access("/sys", F_OK) == 0 || access("/run", F_OK) == 0
      || access("/root/.pm2/rpc.sock", R_OK) == 0 || access("/root/.pm2/pub.sock", R_OK) == 0
      || access("/var/run/docker.sock", F_OK) == 0 || access("/etc/shadow", F_OK) == 0) {
    fail("blocked_resource_exposed");
  }
  errno = 0;
  int write_probe = open(".shellbridge-write-probe", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (write_probe >= 0) {
    close(write_probe);
    unlink(".shellbridge-write-probe");
    fail("persistent_write_exposed");
  }
  if (errno != EROFS && errno != EACCES) fail("persistent_write_check_failed");
  verify_no_capabilities();
  apply_limits(argv[6], argv[7], argv[8], argv[9], argv[10]);
  install_seccomp();
  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) fail("no_new_privileges_failed");
  errno = 0;
  int inet_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (inet_socket >= 0 || errno != EPERM) fail("network_seccomp_failed");
  errno = 0;
  int unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (unix_socket >= 0 || errno != EPERM) fail("unix_socket_seccomp_failed");
  execl("/bin/bash", "bash", "-lc", argv[11], (char *)NULL);
  fail("sandbox_shell_exec_failed");
}

static void drop_bounding_capabilities(void) {
  for (int capability = 0; capability <= 63; capability += 1) {
    if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL) fail("capability_drop_failed");
  }
}

static void observe_command(int argc, char **argv) {
  if (argc != 6 || strcmp(argv[5], "--version") != 0) fail("invalid_helper_request");
  uid_t uid = (uid_t)parse_unsigned(argv[2], UINT_MAX, "invalid_observer_identity");
  gid_t gid = (gid_t)parse_unsigned(argv[3], UINT_MAX, "invalid_observer_identity");
  if (uid == 0 || gid == 0) fail("invalid_observer_identity");
  if (argv[4][0] != '/' || argv[4][1] == '\0') fail("command_unavailable");
  int filesystem_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (filesystem_root < 0) fail("command_unavailable");
  int executable = openat2_beneath(
    filesystem_root,
    argv[4] + 1,
    O_PATH | O_CLOEXEC,
    RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
  );
  close(filesystem_root);
  if (executable < 0) fail("command_unavailable");
  struct stat metadata;
  if (fstat(executable, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0) {
    fail("command_not_trusted");
  }
  if (unshare(CLONE_NEWNET) != 0) fail("command_network_isolation_failed");
  drop_bounding_capabilities();
  if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) fail("observer_identity_failed");
  if (chdir("/") != 0) fail("observer_cwd_failed");
  apply_limits("5", "2147483648", "32", "1048576", "64");
  verify_no_capabilities();
  install_seccomp();
  char *const command_argv[] = { argv[4], "--version", NULL };
  char *const environment[] = { "PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C", NULL };
  syscall(SYS_execveat, executable, "", command_argv, environment, AT_EMPTY_PATH);
  fail("command_exec_failed");
}

static void cgroup_exec(int argc, char **argv) {
  if (argc < 5 || strcmp(argv[3], "--") != 0) fail("invalid_helper_request");
  char signal_byte;
  for (;;) {
    ssize_t count = read(3, &signal_byte, 1);
    if (count == 1) break;
    if (count < 0 && errno == EINTR) continue;
    fail("sandbox_start_signal_failed");
  }
  argv[3] = argv[2];
  execv(argv[2], &argv[3]);
  fail("bwrap_exec_failed");
}

int main(int argc, char **argv) {
  if (argc == 6 && strcmp(argv[1], "secure-read") == 0 && strcmp(argv[2], "--") == 0) {
    secure_read(argv[3], argv[4], argv[5]);
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "validate-tree-fd") == 0) {
    validate_tree_fd(3, 4, 5, argv[2]);
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "validate-disjoint-fds") == 0) {
    validate_disjoint_fds(argv[2], argv[3]);
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "write-seccomp") == 0) {
    write_seccomp(argv[2]);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "sandbox-init") == 0) {
    sandbox_init(argc, argv);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "observe-command") == 0) {
    observe_command(argc, argv);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "cgroup-exec") == 0) {
    cgroup_exec(argc, argv);
    return 0;
  }
  fail("invalid_helper_request");
}
