#define _GNU_SOURCE

/*
 * Fixed diagnostic case: atomically place one blocked child in a private
 * cgroup leaf, observe that placement through the held leaf directory, then
 * let the child create a relative cgroup namespace. Passing does not hide an
 * inherited cgroupfs mount, create a candidate sandbox, or establish backend
 * availability. The helper writes no output and runs no candidate program.
 */

enum probe_exit {
    PROBE_CASE_OBSERVED = 0,
    PROBE_UNAVAILABLE = 2,
    PROBE_UNKNOWN = 3,
    PROBE_CLEANUP_UNCONFIRMED = 4,
};

#if !defined(__linux__)

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        return PROBE_UNKNOWN;
    }
    return PROBE_UNAVAILABLE;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if (!defined(__x86_64__) && !defined(__aarch64__)) || defined(__ILP32__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ || \
    !defined(SYS_clone3) || !defined(SYS_pidfd_send_signal) || \
    !defined(SYS_unshare) || !defined(SYS_waitid)

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        return PROBE_UNKNOWN;
    }
    return PROBE_UNAVAILABLE;
}

#else

#define CONTROL_BYTES_MAX 4096U
#define CGROUP_COMPONENT_BYTES_MAX 255U
#define LEAF_NAME_BYTES 64U
#define CHILD_WAIT_MILLISECONDS 3000
#define CHILD_GATE_WAIT_MILLISECONDS 5000
#define INTERRUPTED_SYSCALL_LIMIT 8U
#define WAITPID_ATTEMPTS 20U
#define WAITPID_DELAY_NANOSECONDS 50000000L
#define PIDFD_IDTYPE 3

static const char CGROUP_ROOT[] = "/sys/fs/cgroup";
static const unsigned char CHILD_RELEASE_TOKEN = 0xa5U;
static const unsigned char CHILD_CANCEL_TOKEN = 0x5aU;
static volatile sig_atomic_t CANCELLATION_REQUESTED = 0;

_Static_assert(sizeof(void *) == 8U, "the probe requires 64-bit pointers");
_Static_assert(sizeof(long) == 8U, "the probe requires 64-bit long");

struct probe_state {
    int current_cgroup_fd;
    int leaf_fd;
    int pidfd;
    int sync_child_fd;
    int sync_parent_fd;
    pid_t child_pid;
    bool leaf_created;
    bool leaf_identity_known;
    bool child_reaped;
    char leaf_name[LEAF_NAME_BYTES];
    char initial_membership[CONTROL_BYTES_MAX];
    size_t initial_membership_length;
    struct stat leaf_identity;
};

static void request_cancellation(int signal_number) {
    (void)signal_number;
    CANCELLATION_REQUESTED = 1;
}

static bool install_cancellation_handlers(void) {
    struct sigaction action;
    struct sigaction child_default;
    sigset_t unblocked;
    memset(&action, 0, sizeof(action));
    memset(&child_default, 0, sizeof(child_default));
    action.sa_handler = request_cancellation;
    child_default.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigemptyset(&child_default.sa_mask) != 0 ||
        sigemptyset(&unblocked) != 0 || sigaddset(&unblocked, SIGTERM) != 0 ||
        sigaddset(&unblocked, SIGINT) != 0 ||
        sigaddset(&unblocked, SIGHUP) != 0 ||
        sigaddset(&unblocked, SIGCHLD) != 0) {
        return false;
    }
    return sigaction(SIGCHLD, &child_default, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGHUP, &action, NULL) == 0 &&
           sigprocmask(SIG_UNBLOCK, &unblocked, NULL) == 0;
}

static bool block_cancellation_signals(void) {
    sigset_t blocked;
    return sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGTERM) == 0 &&
           sigaddset(&blocked, SIGINT) == 0 &&
           sigaddset(&blocked, SIGHUP) == 0 &&
           sigprocmask(SIG_BLOCK, &blocked, NULL) == 0;
}

static bool close_descriptor(int *descriptor) {
    int result;
    if (*descriptor < 0) {
        return true;
    }
    result = close(*descriptor);
    *descriptor = -1;
    return result == 0;
}

static bool record_directory_identity(int descriptor, struct stat *identity) {
    return fstat(descriptor, identity) == 0 && S_ISDIR(identity->st_mode);
}

static bool root_owns_nonwritable_directory(int descriptor) {
    struct stat identity;
    return fstat(descriptor, &identity) == 0 && S_ISDIR(identity.st_mode) &&
           identity.st_uid == 0U && (identity.st_mode & 0022U) == 0U;
}

static bool root_owns_nonwritable_control(int directory, const char *name) {
    struct stat identity;
    int descriptor = openat(
        directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    );
    bool trusted;
    if (descriptor < 0) {
        return false;
    }
    trusted = fstat(descriptor, &identity) == 0 && S_ISREG(identity.st_mode) &&
              identity.st_uid == 0U && (identity.st_mode & 0022U) == 0U;
    if (!close_descriptor(&descriptor)) {
        trusted = false;
    }
    return trusted;
}

static bool root_owns_nonwritable_migration_controls(int directory) {
    return root_owns_nonwritable_control(directory, "cgroup.procs") &&
           root_owns_nonwritable_control(directory, "cgroup.threads");
}

static bool path_matches_directory_identity(
    int parent, const char *name, const struct stat *identity
) {
    struct stat observed;
    return fstatat(parent, name, &observed, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISDIR(observed.st_mode) && observed.st_dev == identity->st_dev &&
           observed.st_ino == identity->st_ino;
}

static bool read_descriptor_bounded(
    int descriptor, char *buffer, size_t capacity, size_t *length
) {
    size_t used = 0U;
    unsigned int interruptions = 0U;
    while (used < capacity) {
        ssize_t observed = read(descriptor, buffer + used, capacity - used);
        if (observed > 0) {
            used += (size_t)observed;
            continue;
        }
        if (observed == 0) {
            *length = used;
            return true;
        }
        if (errno != EINTR) {
            return false;
        }
        ++interruptions;
        if (interruptions > INTERRUPTED_SYSCALL_LIMIT) {
            return false;
        }
    }
    {
        char extra;
        ssize_t observed = read(descriptor, &extra, 1U);
        if (observed == 0) {
            *length = used;
            return true;
        }
    }
    return false;
}

static bool read_control_file(
    int directory, const char *name, char *buffer, size_t capacity, size_t *length
) {
    int descriptor = openat(
        directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    );
    bool success;
    if (descriptor < 0) {
        return false;
    }
    success = read_descriptor_bounded(descriptor, buffer, capacity, length);
    if (!close_descriptor(&descriptor)) {
        success = false;
    }
    return success;
}

static bool read_absolute_file(
    const char *path, char *buffer, size_t capacity, size_t *length
) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    bool success;
    if (descriptor < 0) {
        return false;
    }
    success = read_descriptor_bounded(descriptor, buffer, capacity, length);
    if (!close_descriptor(&descriptor)) {
        success = false;
    }
    return success;
}

static bool read_current_membership(
    char *buffer, size_t capacity, size_t *length
) {
    static const char prefix[] = "0::/";
    size_t index;
    if (!read_absolute_file("/proc/self/cgroup", buffer, capacity, length) ||
        *length < sizeof(prefix) ||
        memcmp(buffer, prefix, sizeof(prefix) - 1U) != 0 ||
        buffer[*length - 1U] != '\n') {
        return false;
    }
    for (index = 0U; index + 1U < *length; ++index) {
        if (buffer[index] == '\0' || buffer[index] == '\n' ||
            buffer[index] == '\r') {
            return false;
        }
    }
    index = sizeof(prefix) - 1U;
    while (index + 1U < *length) {
        size_t start = index;
        while (index + 1U < *length && buffer[index] != '/') {
            ++index;
        }
        if (index == start || index - start > CGROUP_COMPONENT_BYTES_MAX ||
            (index - start == 1U && buffer[start] == '.') ||
            (index - start == 2U && buffer[start] == '.' &&
             buffer[start + 1U] == '.')) {
            return false;
        }
        if (index + 1U < *length) {
            ++index;
            if (index + 1U == *length) {
                return false;
            }
        }
    }
    return true;
}

static int open_membership_directory(const char *membership, size_t length) {
    struct statfs filesystem;
    size_t index = sizeof("0::/") - 1U;
    int descriptor = open(
        CGROUP_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (descriptor < 0 || fstatfs(descriptor, &filesystem) != 0 ||
        (unsigned long)filesystem.f_type != (unsigned long)CGROUP2_SUPER_MAGIC ||
        !root_owns_nonwritable_directory(descriptor) ||
        !root_owns_nonwritable_migration_controls(descriptor)) {
        (void)close_descriptor(&descriptor);
        return -1;
    }
    while (index + 1U < length) {
        char component[CGROUP_COMPONENT_BYTES_MAX + 1U];
        size_t start = index;
        size_t component_length;
        int next_descriptor;
        while (index + 1U < length && membership[index] != '/') {
            ++index;
        }
        component_length = index - start;
        if (component_length == 0U ||
            component_length > CGROUP_COMPONENT_BYTES_MAX) {
            (void)close_descriptor(&descriptor);
            return -1;
        }
        memcpy(component, membership + start, component_length);
        component[component_length] = '\0';
        next_descriptor = openat(
            descriptor,
            component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        );
        if (next_descriptor < 0) {
            (void)close_descriptor(&descriptor);
            return -1;
        }
        if (!root_owns_nonwritable_directory(next_descriptor) ||
            !root_owns_nonwritable_migration_controls(next_descriptor)) {
            (void)close_descriptor(&next_descriptor);
            (void)close_descriptor(&descriptor);
            return -1;
        }
        if (!close_descriptor(&descriptor)) {
            (void)close_descriptor(&next_descriptor);
            return -1;
        }
        descriptor = next_descriptor;
        if (index + 1U < length) {
            ++index;
        }
    }
    return descriptor;
}

static bool is_space(char value) {
    return value == ' ' || value == '\n' || value == '\r' || value == '\t';
}

static bool token_equals(
    const char *buffer, size_t start, size_t end, const char *expected
) {
    size_t expected_length = strlen(expected);
    return end - start == expected_length &&
           memcmp(buffer + start, expected, expected_length) == 0;
}

static bool procs_match_pid(
    const char *buffer, size_t length, pid_t expected_pid, bool require_exact
) {
    size_t index = 0U;
    bool observed = false;
    unsigned int entries = 0U;
    if (expected_pid <= 0) {
        return false;
    }
    while (index < length) {
        uint64_t value = 0U;
        bool has_digit = false;
        while (index < length && is_space(buffer[index])) {
            ++index;
        }
        if (index == length) {
            break;
        }
        while (index < length && !is_space(buffer[index])) {
            unsigned int digit;
            if (buffer[index] < '0' || buffer[index] > '9') {
                return false;
            }
            digit = (unsigned int)(buffer[index] - '0');
            if (value > (UINT64_MAX - digit) / 10U) {
                return false;
            }
            value = value * 10U + digit;
            has_digit = true;
            ++index;
        }
        if (!has_digit) {
            return false;
        }
        ++entries;
        if (value == (uint64_t)(unsigned int)expected_pid) {
            observed = true;
        }
    }
    return observed && (!require_exact || entries == 1U);
}

static bool events_match_population(
    const char *buffer, size_t length, const char *expected
) {
    size_t index = 0U;
    unsigned int populated_fields = 0U;
    while (index < length) {
        size_t key_start;
        size_t key_end;
        size_t value_start;
        size_t value_end;
        while (index < length && is_space(buffer[index])) {
            ++index;
        }
        if (index == length) {
            break;
        }
        key_start = index;
        while (index < length && !is_space(buffer[index])) {
            ++index;
        }
        key_end = index;
        while (index < length && is_space(buffer[index])) {
            ++index;
        }
        if (index == length) {
            return false;
        }
        value_start = index;
        while (index < length && !is_space(buffer[index])) {
            ++index;
        }
        value_end = index;
        if (token_equals(buffer, key_start, key_end, "populated")) {
            ++populated_fields;
            if (!token_equals(buffer, value_start, value_end, expected)) {
                return false;
            }
        }
    }
    return populated_fields == 1U;
}

static bool leaf_population_is(struct probe_state *state, const char *expected) {
    char buffer[CONTROL_BYTES_MAX];
    size_t length = 0U;
    return state->leaf_fd >= 0 &&
           root_owns_nonwritable_control(state->leaf_fd, "cgroup.events") &&
           read_control_file(
               state->leaf_fd,
               "cgroup.events",
               buffer,
               sizeof(buffer),
               &length
           ) &&
           events_match_population(buffer, length, expected);
}

static bool current_membership_matches(const struct probe_state *state) {
    char membership[CONTROL_BYTES_MAX];
    size_t length = 0U;
    return read_current_membership(membership, sizeof(membership), &length) &&
           length == state->initial_membership_length &&
           memcmp(membership, state->initial_membership, length) == 0;
}

static bool current_directory_contains_self(struct probe_state *state) {
    char buffer[CONTROL_BYTES_MAX];
    size_t length = 0U;
    return state->current_cgroup_fd >= 0 &&
           root_owns_nonwritable_directory(state->current_cgroup_fd) &&
           root_owns_nonwritable_migration_controls(
               state->current_cgroup_fd
           ) &&
           read_control_file(
               state->current_cgroup_fd,
               "cgroup.procs",
               buffer,
               sizeof(buffer),
               &length
           ) &&
           procs_match_pid(buffer, length, getpid(), false) &&
           current_membership_matches(state);
}

static bool random_leaf_name(char *name, size_t capacity) {
    static const char prefix[] = "forge-probe-";
    static const char hexadecimal[] = "0123456789abcdef";
    unsigned char random_value[16U];
    size_t index;
    ssize_t observed = -1;
    unsigned int attempt;
    if (capacity < sizeof(prefix) + 32U) {
        return false;
    }
    for (attempt = 0U; attempt < INTERRUPTED_SYSCALL_LIMIT; ++attempt) {
        observed = getrandom(
            random_value, sizeof(random_value), (unsigned int)GRND_NONBLOCK
        );
        if (observed >= 0 || errno != EINTR) {
            break;
        }
    }
    if (observed != (ssize_t)sizeof(random_value)) {
        return false;
    }
    memcpy(name, prefix, sizeof(prefix) - 1U);
    for (index = 0U; index < sizeof(random_value); ++index) {
        unsigned int byte = random_value[index];
        name[sizeof(prefix) - 1U + index * 2U] = hexadecimal[byte >> 4U];
        name[sizeof(prefix) + index * 2U] = hexadecimal[byte & 0x0fU];
    }
    name[sizeof(prefix) - 1U + 32U] = '\0';
    return true;
}

static bool create_leaf(struct probe_state *state) {
    unsigned int attempt;
    char buffer[CONTROL_BYTES_MAX];
    size_t length = 0U;
    for (attempt = 0U; attempt < 8U; ++attempt) {
        if (!random_leaf_name(state->leaf_name, sizeof(state->leaf_name))) {
            return false;
        }
        if (mkdirat(state->current_cgroup_fd, state->leaf_name, 0700) == 0) {
            state->leaf_created = true;
            break;
        }
        if (errno != EEXIST) {
            return false;
        }
    }
    if (!state->leaf_created) {
        return false;
    }
    state->leaf_fd = openat(
        state->current_cgroup_fd,
        state->leaf_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (state->leaf_fd < 0 ||
        !record_directory_identity(state->leaf_fd, &state->leaf_identity)) {
        return false;
    }
    state->leaf_identity_known = true;
    return root_owns_nonwritable_directory(state->leaf_fd) &&
           root_owns_nonwritable_migration_controls(state->leaf_fd) &&
           root_owns_nonwritable_control(state->leaf_fd, "cgroup.events") &&
           path_matches_directory_identity(
               state->current_cgroup_fd,
               state->leaf_name,
               &state->leaf_identity
           ) &&
           read_control_file(
               state->leaf_fd,
               "cgroup.procs",
               buffer,
               sizeof(buffer),
               &length
           ) &&
           length == 0U && leaf_population_is(state, "0");
}

enum child_instruction {
    CHILD_INSTRUCTION_RELEASE,
    CHILD_INSTRUCTION_CANCEL,
    CHILD_INSTRUCTION_INVALID,
};

static enum child_instruction child_waits_for_instruction(int descriptor) {
    unsigned char token = 0U;
    ssize_t observed = -1;
    unsigned int attempt;
    struct pollfd gate = {
        .fd = descriptor,
        .events = POLLIN,
        .revents = 0,
    };
    int ready = poll(&gate, 1U, CHILD_GATE_WAIT_MILLISECONDS);
    if (ready != 1 || (gate.revents & POLLIN) == 0) {
        return CHILD_INSTRUCTION_INVALID;
    }
    for (attempt = 0U; attempt < INTERRUPTED_SYSCALL_LIMIT; ++attempt) {
        observed = recv(descriptor, &token, 1U, 0);
        if (observed >= 0 || errno != EINTR) {
            break;
        }
    }
    if (observed != 1) {
        return CHILD_INSTRUCTION_INVALID;
    }
    if (token == CHILD_RELEASE_TOKEN) {
        return CHILD_INSTRUCTION_RELEASE;
    }
    if (token == CHILD_CANCEL_TOKEN) {
        return CHILD_INSTRUCTION_CANCEL;
    }
    return CHILD_INSTRUCTION_INVALID;
}

static bool child_closes_inherited_descriptors(struct probe_state *state) {
    bool closed = true;
    if (!close_descriptor(&state->sync_parent_fd)) {
        closed = false;
    }
    if (!close_descriptor(&state->current_cgroup_fd)) {
        closed = false;
    }
    if (!close_descriptor(&state->leaf_fd)) {
        closed = false;
    }
    return closed;
}

static bool child_installs_default_cancellation_signals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        return false;
    }
    return sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGHUP, &action, NULL) == 0 &&
           CANCELLATION_REQUESTED == 0;
}

static bool child_observes_namespace_root(void) {
    static const char expected[] = "0::/\n";
    char buffer[CONTROL_BYTES_MAX];
    size_t length = 0U;
    if (syscall(SYS_unshare, (unsigned long)CLONE_NEWCGROUP) != 0L) {
        return false;
    }
    if (!read_absolute_file(
            "/proc/self/cgroup", buffer, sizeof(buffer), &length
        )) {
        return false;
    }
    return length == sizeof(expected) - 1U &&
           memcmp(buffer, expected, sizeof(expected) - 1U) == 0;
}

static bool send_instruction(int descriptor, unsigned char instruction) {
    ssize_t sent = -1;
    unsigned int attempt;
    for (attempt = 0U; attempt < INTERRUPTED_SYSCALL_LIMIT; ++attempt) {
        sent = send(descriptor, &instruction, 1U, MSG_NOSIGNAL);
        if (sent >= 0 || errno != EINTR) {
            break;
        }
    }
    return sent == 1;
}

static bool observe_pidfd(int pidfd, int timeout_milliseconds, bool *exited) {
    struct pollfd descriptor = {
        .fd = pidfd,
        .events = POLLIN,
        .revents = 0,
    };
    int result = poll(&descriptor, 1U, timeout_milliseconds);
    if (result == 0) {
        *exited = false;
        return true;
    }
    if (result == 1 && (descriptor.revents & POLLIN) != 0) {
        *exited = true;
        return true;
    }
    return false;
}

static bool wait_for_pidfd(int pidfd) {
    bool exited = false;
    return observe_pidfd(pidfd, CHILD_WAIT_MILLISECONDS, &exited) && exited;
}

static bool wait_on_pidfd(int pidfd, siginfo_t *information) {
    long result = syscall(
        SYS_waitid,
        PIDFD_IDTYPE,
        (unsigned int)pidfd,
        information,
        WEXITED,
        NULL
    );
    return result == 0L;
}

static enum probe_exit reap_child_normally(struct probe_state *state) {
    siginfo_t information;
    pid_t second_wait;
    memset(&information, 0, sizeof(information));
    if (!wait_on_pidfd(state->pidfd, &information)) {
        return PROBE_UNKNOWN;
    }
    if (information.si_pid != state->child_pid || information.si_code != CLD_EXITED) {
        return PROBE_UNKNOWN;
    }
    state->child_reaped = true;
    errno = 0;
    second_wait = waitpid(state->child_pid, NULL, WNOHANG);
    if (second_wait != -1 || errno != ECHILD) {
        return PROBE_UNKNOWN;
    }
    if (information.si_status == PROBE_CASE_OBSERVED) {
        return PROBE_CASE_OBSERVED;
    }
    if (information.si_status == PROBE_UNAVAILABLE) {
        return PROBE_UNAVAILABLE;
    }
    return PROBE_UNKNOWN;
}

static bool reap_child_for_cleanup(struct probe_state *state) {
    siginfo_t information;
    memset(&information, 0, sizeof(information));
    if (!wait_on_pidfd(state->pidfd, &information)) {
        return false;
    }
    if (information.si_pid != state->child_pid) {
        return false;
    }
    state->child_reaped = true;
    return true;
}

static bool cancel_and_reap_child(struct probe_state *state) {
    bool descriptors_clean = true;
    unsigned int attempt;
    if (state->child_pid <= 0 || state->child_reaped) {
        return true;
    }
    if (state->sync_parent_fd >= 0) {
        (void)send_instruction(state->sync_parent_fd, CHILD_CANCEL_TOKEN);
    }
    if (!close_descriptor(&state->sync_parent_fd)) {
        descriptors_clean = false;
    }
    if (state->pidfd >= 0) {
        if (wait_for_pidfd(state->pidfd) && reap_child_for_cleanup(state)) {
            return descriptors_clean;
        }
        if (syscall(
                SYS_pidfd_send_signal,
                state->pidfd,
                SIGKILL,
                NULL,
                0U
            ) != 0L &&
            errno != ESRCH) {
            return false;
        }
        return wait_for_pidfd(state->pidfd) &&
               reap_child_for_cleanup(state) && descriptors_clean;
    }
    for (attempt = 0U; attempt < WAITPID_ATTEMPTS; ++attempt) {
        struct timespec delay = {
            .tv_sec = 0,
            .tv_nsec = WAITPID_DELAY_NANOSECONDS,
        };
        pid_t observed = waitpid(state->child_pid, NULL, WNOHANG);
        if (observed == state->child_pid) {
            state->child_reaped = true;
            return descriptors_clean;
        }
        if (observed < 0 && errno != EINTR) {
            return false;
        }
        (void)nanosleep(&delay, NULL);
    }
    return false;
}

static enum probe_exit start_and_observe_child(struct probe_state *state) {
    struct clone_args arguments;
    long clone_result;
    int descriptor_flags;
    int synchronization[2] = {-1, -1};
    if (CANCELLATION_REQUESTED != 0 || socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0,
            synchronization
        ) != 0) {
        return PROBE_UNAVAILABLE;
    }
    state->sync_child_fd = synchronization[0];
    state->sync_parent_fd = synchronization[1];
    memset(&arguments, 0, sizeof(arguments));
    arguments.flags = (__u64)CLONE_INTO_CGROUP | (__u64)CLONE_PIDFD;
    arguments.pidfd = (__u64)(uintptr_t)&state->pidfd;
    arguments.cgroup = (__u64)(unsigned int)state->leaf_fd;
    arguments.exit_signal = (__u64)SIGCHLD;
    clone_result = syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (clone_result == 0L) {
        enum child_instruction instruction;
        if (!child_closes_inherited_descriptors(state) ||
            !child_installs_default_cancellation_signals()) {
            _exit(PROBE_UNKNOWN);
        }
        instruction = child_waits_for_instruction(state->sync_child_fd);
        if (instruction == CHILD_INSTRUCTION_CANCEL) {
            _exit(PROBE_UNAVAILABLE);
        }
        if (instruction != CHILD_INSTRUCTION_RELEASE) {
            _exit(PROBE_UNKNOWN);
        }
        _exit(
            child_observes_namespace_root() ? PROBE_CASE_OBSERVED
                                            : PROBE_UNAVAILABLE
        );
    }
    if (clone_result < 0L || clone_result > (long)INT32_MAX) {
        return PROBE_UNAVAILABLE;
    }
    state->child_pid = (pid_t)clone_result;
    if (state->pidfd < 0) {
        return PROBE_UNKNOWN;
    }
    descriptor_flags = fcntl(state->pidfd, F_GETFD);
    if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0) {
        return PROBE_UNKNOWN;
    }
    if (!close_descriptor(&state->sync_child_fd)) {
        return PROBE_UNKNOWN;
    }
    if (CANCELLATION_REQUESTED != 0) {
        return PROBE_UNKNOWN;
    }
    {
        char buffer[CONTROL_BYTES_MAX];
        size_t length = 0U;
        bool exited = false;
        if (!observe_pidfd(state->pidfd, 0, &exited) || exited ||
            !read_control_file(
                state->leaf_fd,
                "cgroup.procs",
                buffer,
                sizeof(buffer),
                &length
            ) ||
            !procs_match_pid(buffer, length, state->child_pid, true) ||
            !leaf_population_is(state, "1") ||
            !observe_pidfd(state->pidfd, 0, &exited) || exited) {
            return PROBE_UNAVAILABLE;
        }
    }
    if (CANCELLATION_REQUESTED != 0) {
        return PROBE_UNKNOWN;
    }
    if (!send_instruction(state->sync_parent_fd, CHILD_RELEASE_TOKEN)) {
        return PROBE_UNAVAILABLE;
    }
    if (!close_descriptor(&state->sync_parent_fd)) {
        return PROBE_UNKNOWN;
    }
    if (!wait_for_pidfd(state->pidfd)) {
        return PROBE_UNAVAILABLE;
    }
    return reap_child_normally(state);
}

static bool clean_probe_state(struct probe_state *state) {
    struct stat status;
    bool clean = cancel_and_reap_child(state);
    bool leaf_identity_matches = false;
    if (!close_descriptor(&state->sync_child_fd)) {
        clean = false;
    }
    if (!close_descriptor(&state->sync_parent_fd)) {
        clean = false;
    }
    if (!close_descriptor(&state->pidfd)) {
        clean = false;
    }
    if (state->leaf_created) {
        if (state->child_pid > 0 && !state->child_reaped) {
            clean = false;
        } else if (!leaf_population_is(state, "0")) {
            clean = false;
        }
        leaf_identity_matches =
            state->leaf_identity_known && state->current_cgroup_fd >= 0 &&
            path_matches_directory_identity(
                state->current_cgroup_fd,
                state->leaf_name,
                &state->leaf_identity
            );
        if (!close_descriptor(&state->leaf_fd)) {
            clean = false;
        }
        if (!leaf_identity_matches) {
            clean = false;
        } else if (unlinkat(
                       state->current_cgroup_fd,
                       state->leaf_name,
                       AT_REMOVEDIR
                   ) != 0) {
            clean = false;
        } else {
            state->leaf_created = false;
            errno = 0;
            if (fstatat(
                    state->current_cgroup_fd,
                    state->leaf_name,
                    &status,
                    AT_SYMLINK_NOFOLLOW
                ) == 0 ||
                errno != ENOENT) {
                clean = false;
            }
        }
    } else if (!close_descriptor(&state->leaf_fd)) {
        clean = false;
    }
    if (state->current_cgroup_fd >= 0 &&
        !current_directory_contains_self(state)) {
        clean = false;
    }
    if (!close_descriptor(&state->current_cgroup_fd)) {
        clean = false;
    }
    return clean;
}

static enum probe_exit run_probe(struct probe_state *state) {
    enum probe_exit child_result;
    if (geteuid() != 0U) {
        return PROBE_UNAVAILABLE;
    }
    if (CANCELLATION_REQUESTED != 0) {
        return PROBE_UNKNOWN;
    }
    if (!read_current_membership(
            state->initial_membership,
            sizeof(state->initial_membership),
            &state->initial_membership_length
        )) {
        return PROBE_UNAVAILABLE;
    }
    state->current_cgroup_fd = open_membership_directory(
        state->initial_membership, state->initial_membership_length
    );
    if (state->current_cgroup_fd < 0 ||
        !current_directory_contains_self(state)) {
        return PROBE_UNAVAILABLE;
    }
    if (!create_leaf(state)) {
        return PROBE_UNAVAILABLE;
    }
    if (CANCELLATION_REQUESTED != 0) {
        return PROBE_UNKNOWN;
    }
    child_result = start_and_observe_child(state);
    if (child_result != PROBE_CASE_OBSERVED) {
        return child_result;
    }
    if (!leaf_population_is(state, "0")) {
        return PROBE_UNAVAILABLE;
    }
    if (CANCELLATION_REQUESTED != 0) {
        return PROBE_UNKNOWN;
    }
    return PROBE_CASE_OBSERVED;
}

int main(int argc, char **argv) {
    struct probe_state state = {
        .current_cgroup_fd = -1,
        .leaf_fd = -1,
        .pidfd = -1,
        .sync_child_fd = -1,
        .sync_parent_fd = -1,
        .child_pid = -1,
        .leaf_created = false,
        .leaf_identity_known = false,
        .child_reaped = false,
        .leaf_name = {0},
        .initial_membership = {0},
        .initial_membership_length = 0U,
        .leaf_identity = {0},
    };
    enum probe_exit result;
    bool cleaned;
    (void)argv;
    if (argc != 1) {
        return PROBE_UNKNOWN;
    }
    if (!install_cancellation_handlers()) {
        return PROBE_UNKNOWN;
    }
    result = run_probe(&state);
    cleaned = clean_probe_state(&state);
    if (!cleaned) {
        return PROBE_CLEANUP_UNCONFIRMED;
    }
    if (result == PROBE_CASE_OBSERVED &&
        (!block_cancellation_signals() || CANCELLATION_REQUESTED != 0)) {
        return PROBE_UNKNOWN;
    }
    return result;
}

#endif
#endif
