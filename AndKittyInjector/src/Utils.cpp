#include "Utils.hpp"
#include <KittyUtils.hpp>

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

namespace Utils
{
    bool android_launch_app(const std::string &pkg)
    {
        std::string activity = _resolveActivity(pkg);
        if (!activity.empty())
        {
            KittyUtils::String::trim(activity);

            std::string result = _execCmd("am start -n " + activity + " 2>&1");
            if (!KittyUtils::String::contains(result, "Error:", false) &&
                !KittyUtils::String::contains(result, "does not exist", false) &&
                !KittyUtils::String::contains(result, "Exception occurred", false) &&
                !KittyUtils::String::contains(result, "Bad component name", false))
            {
                return true;
            }
        }

        // fallback monkey
        std::string monkeyCmd = "monkey -p " + pkg + " --pct-syskeys 0 --pct-anyevent 0 --pct-rotation 0 1 > /dev/null 2>&1";
        if (system(monkeyCmd.c_str()) == 0)
            return true;

        return false;
    }

    bool android_stop_app(const std::string &pkg)
    {
        std::string cmd = "am force-stop " + pkg + " > /dev/null 2>&1";
        system(cmd.c_str());

        usleep(500000); // 500 ms

        return true;
    }

    bool android_restart_app(const std::string &pkg)
    {
        android_stop_app(pkg);
        return android_launch_app(pkg);
    }

    bool inotify_watch_directory(int fd,
                                 const std::string &path,
                                 uint32_t mask,
                                 std::function<bool(int wd, struct inotify_event *event)> cb)
    {
        int wd = inotify_add_watch(fd, path.c_str(), mask);
        if (wd < 0)
            return false;

        bool ok = true;
        char buffer[1024] = {0};
        for (;;)
        {
            memset(buffer, 0, sizeof(buffer));
            auto bytes = KT_EINTR_RETRY(read(fd, buffer, 1024));
            if (bytes < 0)
            {
                ok = false;
                goto end;
            }

            int offset = 0;
            while (offset < bytes)
            {
                auto event = reinterpret_cast<inotify_event *>(&buffer[offset]);

                if (cb(wd, event))
                    goto end;

                offset += offsetof(inotify_event, name) + event->len;
            }
        }

    end:
        inotify_rm_watch(fd, wd);

        return ok;
    }

    // https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp
    bool am_process_start_callback(std::function<void()> init_cb,
                                   std::function<bool(const android_event_am_proc_start *)> cb)
    {
        char log_tag[0xff] = {0};
        int log_tag_get = __system_property_get("persist.log.tag", log_tag);

        bool first = true;
        __system_property_set("persist.log.tag", "");

        auto logger_list = android_logger_list_alloc(0, 1, 0);
        if (logger_list == nullptr)
        {
            KITTY_LOGE("am_process_start_cb: android_logger_list_alloc failed.");
            if (log_tag_get > 0 && log_tag[0] != 0)
                __system_property_set("persist.log.tag", log_tag);
            return false;
        }

        errno = 0;
        auto *logger = android_logger_open(logger_list, LOG_ID_EVENTS);
        if (logger == nullptr)
        {
            KITTY_LOGE("am_process_start_cb: android_logger_open failed.");
            if (log_tag_get > 0 && log_tag[0] != 0)
                __system_property_set("persist.log.tag", log_tag);
            return false;
        }

        bool ok = true;
        struct log_msg msg{};
        while (true)
        {
            if (android_logger_list_read(logger_list, &msg) <= 0)
            {
                ok = false;
                KITTY_LOGE("am_process_start_cb: android_logger_open failed.");
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

            if (event_header->tag != 30014)
                continue;

            if (cb(reinterpret_cast<const android_event_am_proc_start *>(event_header)))
                break;
        }

        if (logger_list)
            android_logger_list_free(logger_list);

        if (log_tag_get > 0 && log_tag[0] != 0)
            __system_property_set("persist.log.tag", log_tag);

        return ok;
    }

} // namespace Utils
