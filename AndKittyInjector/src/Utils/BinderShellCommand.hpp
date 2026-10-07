#pragma once

#include <string>
#include <vector>

// Runs `cmd <service> <args...>` over binder (SHELL_COMMAND_TRANSACTION),
// without spawning a process. For use when execve is blocked by SELinux.
namespace BinderShell
{
    // Captures the command's stdout+stderr into `out`. Returns true if the
    // transaction completed (check `out` for command-level errors).
    bool run(const std::string &service, const std::vector<std::string> &args, std::string &out);
} // namespace BinderShell
