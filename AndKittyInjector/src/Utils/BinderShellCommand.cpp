#include "BinderShellCommand.hpp"

#include <cstdint>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>

#include <KittyUtils.hpp>

#define SHELL_COMMAND_TRANSACTION 0x5f434d44u // '_CMD'
#define CHECK_SERVICE_TRANSACTION 2u          // IServiceManager::CHECK_SERVICE
#define SVC_MGR_INTERFACE "android.os.IServiceManager"

#ifndef FLAT_BINDER_FLAG_ACCEPTS_FDS
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100
#endif

namespace
{
    // Minimal android Parcel writer.
    struct Parcel
    {
        uint8_t buf[8192] = {0};
        size_t pos = 0;
        binder_size_t offs[16] = {0};
        size_t noff = 0;

        void w32(uint32_t v)
        {
            memcpy(buf + pos, &v, 4);
            pos += 4;
        }

        void wstr16(const std::string &s)
        {
            uint32_t len = (uint32_t)s.size();
            w32(len);
            for (uint32_t i = 0; i < len; i++)
            {
                uint16_t c = (uint8_t)s[i];
                memcpy(buf + pos, &c, 2);
                pos += 2;
            }
            uint16_t z = 0;
            memcpy(buf + pos, &z, 2);
            pos += 2;
            while (pos & 3)
                buf[pos++] = 0;
        }

        void wobj(const flat_binder_object &o)
        {
            offs[noff++] = pos;
            memcpy(buf + pos, &o, sizeof(o));
            pos += sizeof(o);
        }

        void wfd(int fd)
        {
            flat_binder_object o = {};
            o.hdr.type = BINDER_TYPE_FD;
            o.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
            o.handle = fd;
            o.cookie = 0;
            wobj(o);
        }

        void wbinder_null()
        {
            flat_binder_object o = {};
            o.hdr.type = BINDER_TYPE_BINDER;
            o.flags = 0;
            o.binder = 0;
            o.cookie = 0;
            wobj(o);
        }
    };

    // Returns 1 on BR_REPLY, 0 on failed/dead reply, -1 otherwise.
    int parse_reply(int fd, uint8_t *buf, size_t sz, int64_t *out_handle)
    {
        size_t off = 0;
        while (off + 4 <= sz)
        {
            uint32_t cmd = *(uint32_t *)(buf + off);
            off += 4;
            switch (cmd)
            {
            case BR_TRANSACTION_COMPLETE:
            case BR_NOOP:
            case BR_SPAWN_LOOPER:
                break;
            case BR_INCREFS:
            case BR_ACQUIRE:
            case BR_RELEASE:
            case BR_DECREFS:
                off += sizeof(binder_uintptr_t) * 2;
                break;
            case BR_REPLY:
            {
                binder_transaction_data *tr = (binder_transaction_data *)(buf + off);
                off += sizeof(*tr);

                uint32_t handle = 0;
                bool have_handle = false;
                if (out_handle && tr->offsets_size >= sizeof(binder_size_t))
                {
                    binder_size_t *o = (binder_size_t *)tr->data.ptr.offsets;
                    flat_binder_object *fo = (flat_binder_object *)((uint8_t *)tr->data.ptr.buffer + o[0]);
                    if (fo->hdr.type == BINDER_TYPE_HANDLE)
                    {
                        *out_handle = fo->handle;
                        handle = fo->handle;
                        have_handle = true;
                    }
                }

                // Acquire a ref before freeing the buffer, else the handle dies.
                if (have_handle)
                {
                    struct
                    {
                        uint32_t c1, h1, c2, h2;
                    } __attribute__((packed)) acq{BC_ACQUIRE, handle, BC_INCREFS, handle};
                    binder_write_read w = {};
                    w.write_size = sizeof(acq);
                    w.write_buffer = (binder_uintptr_t)&acq;
                    ioctl(fd, BINDER_WRITE_READ, &w);
                }

                struct
                {
                    uint32_t c;
                    binder_uintptr_t p;
                } __attribute__((packed)) fb{BC_FREE_BUFFER, tr->data.ptr.buffer};
                binder_write_read w = {};
                w.write_size = sizeof(fb);
                w.write_buffer = (binder_uintptr_t)&fb;
                ioctl(fd, BINDER_WRITE_READ, &w);
                return 1;
            }
            case BR_DEAD_REPLY:
            case BR_FAILED_REPLY:
                return 0;
            default:
                return -1;
            }
        }
        return -1;
    }

    int transact(int fd, uint32_t handle, uint32_t code, Parcel *p, int64_t *out_handle)
    {
        uint8_t wbuf[256] = {0};
        *(uint32_t *)wbuf = BC_TRANSACTION;
        binder_transaction_data *tr = (binder_transaction_data *)(wbuf + 4);
        tr->target.handle = handle;
        tr->code = code;
        tr->flags = 0;
        tr->data_size = p ? p->pos : 0;
        tr->offsets_size = p ? p->noff * sizeof(binder_size_t) : 0;
        tr->data.ptr.buffer = (p && p->pos) ? (binder_uintptr_t)p->buf : 0;
        tr->data.ptr.offsets = (p && p->noff) ? (binder_uintptr_t)p->offs : 0;

        uint8_t rbuf[2048] = {0};
        binder_write_read bwr = {};
        bwr.write_size = 4 + sizeof(binder_transaction_data);
        bwr.write_buffer = (binder_uintptr_t)wbuf;
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (binder_uintptr_t)rbuf;
        if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
            return -2;
        return parse_reply(fd, rbuf, bwr.read_consumed, out_handle);
    }

    int64_t get_service(int fd, const std::string &name, int sdk)
    {
        Parcel p;
        p.w32(0); // strict mode policy
        if (sdk >= 29)
            p.w32((uint32_t)-1); // Android 10+ work source field
        p.wstr16(SVC_MGR_INTERFACE);
        p.wstr16(name);
        int64_t h = -1;
        if (transact(fd, 0, CHECK_SERVICE_TRANSACTION, &p, &h) != 1)
            return -1;
        return h;
    }
} // namespace

namespace BinderShell
{
    bool run(const std::string &service, const std::vector<std::string> &args, std::string &out)
    {
        out.clear();

        int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return false;

        // BINDER_VERSION before mmap (matches libbinder; required on some kernels).
        binder_version bv{};
        if (ioctl(fd, BINDER_VERSION, &bv) < 0)
        {
            close(fd);
            return false;
        }

        void *vm = mmap(nullptr, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0);
        if (vm == MAP_FAILED)
        {
            close(fd);
            return false;
        }

        const int sdk = KittyUtils::Android::getSDK();

        bool ok = false;
        int devnull = -1, pr = -1, pw = -1;
        do
        {
            int64_t h = get_service(fd, service, sdk);
            if (h <= 0)
                break;

            int pfd[2];
            if (pipe(pfd) != 0)
                break;
            pr = pfd[0];
            pw = pfd[1];
            devnull = open("/dev/null", O_RDWR);
            if (devnull < 0)
                break;

            // shellCommand parcel: in/out/err FDs, argc, args, 2 null binders.
            Parcel p;
            p.wfd(devnull);
            p.wfd(pw);
            p.wfd(pw);
            p.w32((uint32_t)args.size());
            for (const auto &a : args)
                p.wstr16(a);
            p.wbinder_null(); // IShellCallback
            p.wbinder_null(); // IResultReceiver

            int r = transact(fd, (uint32_t)h, SHELL_COMMAND_TRANSACTION, &p, nullptr);

            close(pw); // close our write end so the reader sees EOF
            pw = -1;

            if (r == 1)
            {
                char tmp[1024];
                ssize_t n;
                while ((n = KT_EINTR_RETRY(read(pr, tmp, sizeof(tmp)))) > 0)
                    out.append(tmp, (size_t)n);
                ok = true;
            }
        } while (false);

        if (pw >= 0)
            close(pw);
        if (pr >= 0)
            close(pr);
        if (devnull >= 0)
            close(devnull);
        munmap(vm, 128 * 1024);
        close(fd);
        return ok;
    }
} // namespace BinderShell
