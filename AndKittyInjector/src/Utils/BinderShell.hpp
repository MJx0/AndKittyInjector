#pragma once

#include <string>
#include <vector>

/// @brief Runs `cmd`/`dumpsys` against a service via binder, no process spawned.
namespace BinderShell
{
    /// @brief Equivalent to `cmd <service> <args...>`. Captures stdout+stderr into OutOutput.
    bool Run(const std::string &Service, const std::vector<std::string> &Args, std::string &OutOutput);

    /// @brief Equivalent to `dumpsys <service> <args...>`. Captures the dump into OutOutput.
    bool Dump(const std::string &Service, const std::vector<std::string> &Args, std::string &OutOutput);
} // namespace BinderShell