#include "Utils.hpp"

#include "BinderShellCommand.hpp"

#include <KittyUtils.hpp>
#include <KittyIOFile.hpp>
#include <KittyMemoryEx.hpp>


static std::string _execCmd(const std::string &cmd)
{
    std::array<char, 256> buffer;
    std::string result;

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        return "";

    while (fgets(buffer.data(), buffer.size(), pipe))
    {
        result += buffer.data();
    }

    pclose(pipe);

    if (!result.empty() && result.back() == '\n')
        result.pop_back();

    return result;
}

static bool _isValidPackageName(const std::string &pkg)
{
    if (pkg.empty())
        return false;

    for (char c : pkg)
    {
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_'))
            return false;
    }

    return true;
}

static bool _isValidActivity(const std::string &pkg, const std::string &act)
{
    if (act.empty())
        return false;

    size_t slash = act.find('/');
    if (slash == std::string::npos)
        return false;
    if (act.find('/', slash + 1) != std::string::npos)
        return false;

    if (act.rfind(pkg + "/", 0) != 0)
        return false;

    std::string cls = act.substr(slash + 1);
    if (cls.empty())
        return false;

    bool has_dot = false;

    for (char c : act)
    {
        if (c == ' ' || c == '\t' || c == '\n')
            return false;
        if (c == '.')
            has_dot = true;
        if (!(isalnum((unsigned char)c) || c == '.' || c == '/' || c == '$'))
            return false;
    }

    return has_dot;
}

static std::string _resolveActivity(const std::string &pkg)
{
    if (!_isValidPackageName(pkg))
        return "";

    std::string act = _execCmd("cmd package resolve-activity --brief " + pkg + " 2>/dev/null | tail -n 1");
    if (_isValidActivity(pkg, act))
        return act;

    // fallback dumpsys
    act = _execCmd("dumpsys package " + pkg + " | grep -A 2 'android.intent.action.MAIN' | grep -o '" + pkg +
                   "/[^ ]*' | head -n 1");
    if (_isValidActivity(pkg, act))
        return act;

    return "";
}

static bool _amhasLaunchError(const std::string &result)
{
    return KittyUtils::String::contains(result, "Error:", false) ||
           KittyUtils::String::contains(result, "does not exist", false) ||
           KittyUtils::String::contains(result, "Exception occurred", false) ||
           KittyUtils::String::contains(result, "Bad component name", false);
}

static bool _amStartApp(const std::string &pkg)
{
    std::string activity = _resolveActivity(pkg);
    if (activity.empty())
    {
        // KITTY_LOGW("amStartApp: Failed to resolve activity for %s", pkg.c_str());
        return false;
    }

    KittyUtils::String::trim(activity);
    std::string result = _execCmd("am start -n " + activity + " 2>&1");
    // KITTY_LOGW("amStartApp: %s", result.c_str());

    return !_amhasLaunchError(result);
}

static bool _monkeyLaunchApp(const std::string &pkg)
{
    std::string cmd = "monkey -p " + pkg + " --pct-syskeys 0 --pct-anyevent 0 --pct-rotation 0 1 > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

// am/cmd/monkey. Needs API 24+ (SHELL_COMMAND_TRANSACTION, added in N).
static bool _binderLaunchApp(const std::string &pkg)
{
    if (KittyUtils::Android::getSDK() < 24)
        return false;

    // cmd package resolve-activity --brief <pkg>
    std::string activity;
    std::string out;
    if (BinderShell::run("package", {"resolve-activity", "--brief", pkg}, out))
    {
        std::stringstream ss(out);
        std::string line;
        while (std::getline(ss, line))
        {
            KittyUtils::String::trim(line);
            if (!line.empty() && line.find('/') != std::string::npos)
                activity = line; // keep the last component-looking line
        }
    }

    if (!_isValidActivity(pkg, activity))
    {
        // KITTY_LOGW("binderLaunchApp: %s", out.c_str());
        return false;
    }

    // cmd activity start-activity -n <component>
    std::string result;
    if (BinderShell::run("activity", {"start-activity", "-n", activity}, result) && !_amhasLaunchError(result))
        return true;

    // KITTY_LOGW("binderLaunchApp: %s", result.c_str());

    return false;
}

namespace Utils
{
    bool android_launch_app(const std::string &pkg)
    {
        if (!_isValidPackageName(pkg))
            return false;

        return _binderLaunchApp(pkg) || _amStartApp(pkg) || _monkeyLaunchApp(pkg);
    }

    bool android_stop_app(const std::string &pkg)
    {
        if (!_isValidPackageName(pkg))
            return false;

        _execCmd("am force-stop " + pkg + " 2>/dev/null");
        {
            std::string out;
            BinderShell::run("activity", {"force-stop", pkg}, out);
        }

        for (int i = 0; i < 250; i++)
        {
            std::vector<pid_t> pids = KittyMemoryEx::getProcessIDs(pkg);
            if (pids.empty())
                return true;

            for (pid_t p : pids)
                if (p > 0)
                    kill(p, SIGKILL);

            usleep(20000); // 20ms
        }

        bool dead = KittyMemoryEx::getProcessIDs(pkg).empty();
        if (!dead)
            KITTY_LOGE("android_stop_app: %s still alive after stop attempts.", pkg.c_str());

        return dead;
    }

    bool android_restart_app(const std::string &pkg)
    {
        android_stop_app(pkg);
        return android_launch_app(pkg);
    }

    bool kill_process(const std::string &proc)
    {
        for (int i = 0; i < 250; i++)
        {
            std::vector<pid_t> pids = KittyMemoryEx::getProcessIDs(proc);
            if (pids.empty())
                return true;

            for (pid_t p : pids)
                if (p > 0)
                    kill(p, SIGKILL);

            usleep(20000); // 20ms
        }

        bool dead = KittyMemoryEx::getProcessIDs(proc).empty();
        if (!dead)
            KITTY_LOGE("kill_process: %s still alive after stop attempts.", proc.c_str());

        return dead;
    }

    bool is_app_specialized(int pid)
    {
        std::string ctx;
        if (!KittyIOFile::readFileToString(KittyUtils::String::fmt("/proc/%d/attr/current", pid), &ctx))
            return true; // maybe selinux disabled

        return !ctx.empty() && ctx.find("zygote") == std::string::npos;
    }

    SELinuxState selinux_state()
    {
        std::string se = _execCmd("getenforce");
        KittyUtils::String::trim(se);

        if (se == "Enforcing")
            return SELinuxState::Enforcing;
        else if (se == "Permissive")
            return SELinuxState::Permissive;
        else if (se == "Disabled")
            return SELinuxState::Disabled;

        return SELinuxState::Unknown;
    }

    std::string selinux_state_tostr(SELinuxState state)
    {
        if (state == SELinuxState::Enforcing)
            return "Enforcing";
        else if (state == SELinuxState::Permissive)
            return "Permissive";
        else if (state == SELinuxState::Disabled)
            return "Disabled";

        return "Unknown";
    }

    // https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp
    bool am_process_start_callback(std::function<void()> init_cb,
                                   std::function<bool(const android_event_am_proc_start *)> cb)
    {
        constexpr int32_t AM_PROC_START_TAG = 30014; // am_proc_start event tag

        // Temporarily clear persist.log.tag so events aren't filtered out.
        char log_tag[0xff] = {0};
        int log_tag_get = __system_property_get("persist.log.tag", log_tag);
        __system_property_set("persist.log.tag", "");

        auto restore_log_tag = [&]() {
            if (log_tag_get > 0 && log_tag[0] != 0)
                __system_property_set("persist.log.tag", log_tag);
        };

        auto logger_list = android_logger_list_alloc(0, 1, 0);
        if (logger_list == nullptr)
        {
            KITTY_LOGE("am_process_start_cb: android_logger_list_alloc failed.");
            restore_log_tag();
            return false;
        }

        errno = 0;
        auto *logger = android_logger_open(logger_list, LOG_ID_EVENTS);
        if (logger == nullptr)
        {
            KITTY_LOGE("am_process_start_cb: android_logger_open failed.");
            restore_log_tag();
            return false;
        }

        bool ok = true;
        bool first = true;
        struct log_msg msg{};
        while (true)
        {
            if (android_logger_list_read(logger_list, &msg) <= 0)
            {
                ok = false;
                KITTY_LOGE("am_process_start_cb: android_logger_list_read failed.");
                break;
            }

            if (first)
            {
                if (init_cb)
                    init_cb();

                first = false;
                continue;
            }

            auto *event_header = reinterpret_cast<const android_event_header_t *>(&msg.buf[msg.entry.hdr_size]);

            if (event_header->tag != AM_PROC_START_TAG)
                continue;

            if (cb(reinterpret_cast<const android_event_am_proc_start *>(event_header)))
                break;
        }

        if (logger_list)
            android_logger_list_free(logger_list);

        restore_log_tag();

        return ok;
    }

} // namespace Utils
