#include "BinderShell.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <KittyUtils.hpp>
#include <sys/system_properties.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <utility>

#define BS_EINTR_RETRY(exp)                                                                                            \
    ({                                                                                                                 \
        __typeof__(exp) _rc;                                                                                           \
        do                                                                                                             \
        {                                                                                                              \
            _rc = (exp);                                                                                               \
        } while (_rc == -1 && errno == EINTR);                                                                         \
        _rc;                                                                                                           \
    })

namespace
{
#ifndef FLAT_BINDER_FLAG_ACCEPTS_FDS
    constexpr uint32_t kFlatBinderFlagAcceptsFDs = FLAT_BINDER_FLAG_ACCEPTS_FDS;
#else
    constexpr uint32_t kFlatBinderFlagAcceptsFDs = 0x100;
#endif

    constexpr uint32_t kShellCommandTransaction = 0x5f434d44u; // '_CMD'
    constexpr uint32_t kDumpTransaction = 0x5f444d50u;         // '_DMP'
    constexpr uint32_t kCheckServiceTransaction = 2u;          // IServiceManager::CHECK_SERVICE
    constexpr const char *kServiceManagerInterface = "android.os.IServiceManager";

    constexpr uint32_t kInterfaceTokenHeader = 0x53595354u; // 'SYST' - newer libbinder's writeInterfaceToken

    int GetAndroidSdk()
    {
        static int sdk = 0;
        if (sdk > 0)
            return sdk;

        char buff[PROP_VALUE_MAX] = {};
        if (__system_property_get("ro.build.version.sdk", buff) <= 0)
            return -1;

        sdk = std::atoi(buff);
        return sdk;
    }

    /// @brief Minimal Android Parcel writer - just enough to build the requests sent below.
    struct FParcel
    {
        uint8_t Buf[8192] = {};
        size_t Pos = 0;
        binder_size_t Offs[16] = {};
        size_t NumOffs = 0;

        void Write32(uint32_t Value)
        {
            memcpy(Buf + Pos, &Value, 4);
            Pos += 4;
        }

        void WriteString16(const std::string &Str)
        {
            const uint32_t Len = static_cast<uint32_t>(Str.size());
            Write32(Len);
            for (uint32_t i = 0; i < Len; i++)
            {
                const uint16_t Char = static_cast<uint8_t>(Str[i]);
                memcpy(Buf + Pos, &Char, 2);
                Pos += 2;
            }
            const uint16_t Zero = 0;
            memcpy(Buf + Pos, &Zero, 2);
            Pos += 2;
            while (Pos & 3)
                Buf[Pos++] = 0;
        }

        void WriteObject(const flat_binder_object &Object)
        {
            Offs[NumOffs++] = Pos;
            memcpy(Buf + Pos, &Object, sizeof(Object));
            Pos += sizeof(Object);
        }

        void WriteFd(int Fd)
        {
            flat_binder_object Object = {};
            Object.hdr.type = BINDER_TYPE_FD;
            Object.flags = 0x7f | kFlatBinderFlagAcceptsFDs;
            Object.handle = Fd;
            Object.cookie = 0;
            WriteObject(Object);
        }

        void WriteNullBinder()
        {
            flat_binder_object Object = {};
            Object.hdr.type = BINDER_TYPE_BINDER;
            Object.flags = 0;
            Object.binder = 0;
            Object.cookie = 0;
            WriteObject(Object);
        }
    };

    /// @brief Reads one binder reply. Returns 1 on BR_REPLY, 0 on a dead/failed reply, -1 otherwise.
    /// *OutBareReply reports a reply with no binder objects and <=4 bytes of data (Parcel::setError()'s
    /// shape, but also a normal shell-command/dump exit-code reply - the caller decides which).
    int ParseReply(int Fd, uint8_t *Buf, size_t Size, int64_t *OutHandle, bool *OutBareReply = nullptr)
    {
        size_t Off = 0;
        while (Off + 4 <= Size)
        {
            uint32_t Cmd;
            memcpy(&Cmd, Buf + Off, 4);
            Off += 4;

            switch (Cmd)
            {
            case BR_TRANSACTION_COMPLETE:
            case BR_NOOP:
            case BR_SPAWN_LOOPER:
                break;

            case BR_INCREFS:
            case BR_ACQUIRE:
            case BR_RELEASE:
            case BR_DECREFS:
                Off += sizeof(binder_uintptr_t) * 2;
                break;

            case BR_REPLY:
            {
                auto *Tr = reinterpret_cast<binder_transaction_data *>(Buf + Off);
                Off += sizeof(*Tr);

                uint32_t Handle = 0;
                bool bHaveHandle = false;

                if (OutBareReply)
                    *OutBareReply = Tr->offsets_size == 0 && Tr->data_size <= sizeof(uint32_t);

                if (OutHandle && Tr->offsets_size >= sizeof(binder_size_t))
                {
                    auto *Offsets = reinterpret_cast<binder_size_t *>(Tr->data.ptr.offsets);
                    auto *FlatObj = reinterpret_cast<flat_binder_object *>(
                        reinterpret_cast<uint8_t *>(Tr->data.ptr.buffer) + Offsets[0]);

                    if (FlatObj->hdr.type == BINDER_TYPE_HANDLE)
                    {
                        *OutHandle = FlatObj->handle;
                        Handle = FlatObj->handle;
                        bHaveHandle = true;
                    }
                }

                // Acquire a ref before freeing the reply buffer, else the handle dies with it.
                if (bHaveHandle)
                {
                    struct
                    {
                        uint32_t C1, H1, C2, H2;
                    } __attribute__((packed)) Acquire{BC_ACQUIRE, Handle, BC_INCREFS, Handle};

                    binder_write_read Write = {};
                    Write.write_size = sizeof(Acquire);
                    Write.write_buffer = reinterpret_cast<binder_uintptr_t>(&Acquire);
                    ioctl(Fd, BINDER_WRITE_READ, &Write);
                }

                struct
                {
                    uint32_t C;
                    binder_uintptr_t P;
                } __attribute__((packed)) FreeBuf{BC_FREE_BUFFER, Tr->data.ptr.buffer};

                binder_write_read Write = {};
                Write.write_size = sizeof(FreeBuf);
                Write.write_buffer = reinterpret_cast<binder_uintptr_t>(&FreeBuf);
                ioctl(Fd, BINDER_WRITE_READ, &Write);
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

    int Transact(int Fd, uint32_t Handle, uint32_t Code, FParcel *ParcelData, int64_t *OutHandle,
                 bool *OutBareReply = nullptr)
    {
        uint8_t WriteBuf[256] = {};
        *reinterpret_cast<uint32_t *>(WriteBuf) = BC_TRANSACTION;

        auto *Tr = reinterpret_cast<binder_transaction_data *>(WriteBuf + 4);
        Tr->target.handle = Handle;
        Tr->code = Code;
        Tr->flags = 0;
        Tr->data_size = ParcelData ? ParcelData->Pos : 0;
        Tr->offsets_size = ParcelData ? ParcelData->NumOffs * sizeof(binder_size_t) : 0;
        Tr->data.ptr.buffer = (ParcelData && ParcelData->Pos) ? reinterpret_cast<binder_uintptr_t>(ParcelData->Buf) : 0;
        Tr->data.ptr.offsets = (ParcelData && ParcelData->NumOffs)
                                   ? reinterpret_cast<binder_uintptr_t>(ParcelData->Offs)
                                   : 0;

        uint8_t ReadBuf[2048] = {};
        binder_write_read Bwr = {};
        Bwr.write_size = 4 + sizeof(binder_transaction_data);
        Bwr.write_buffer = reinterpret_cast<binder_uintptr_t>(WriteBuf);
        Bwr.read_size = sizeof(ReadBuf);
        Bwr.read_buffer = reinterpret_cast<binder_uintptr_t>(ReadBuf);

        if (ioctl(Fd, BINDER_WRITE_READ, &Bwr) < 0)
            return -2;

        return ParseReply(Fd, ReadBuf, Bwr.read_consumed, OutHandle, OutBareReply);
    }

    int64_t GetService(int Fd, const std::string &Name)
    {
        int Sdk = GetAndroidSdk();

        static int8_t NeedsHeader = 0; // 0 = unknown, 1 = yes, -1 = no

        auto TryOnce = [&](bool WithHeader) {
            FParcel ParcelData;
            ParcelData.Write32(0); // Strict mode policy.
            if (Sdk >= 29)
                ParcelData.Write32(static_cast<uint32_t>(-1)); // Android 10+ work-source field.
            if (WithHeader)
                ParcelData.Write32(kInterfaceTokenHeader);
            ParcelData.WriteString16(kServiceManagerInterface);
            ParcelData.WriteString16(Name);

            int64_t Handle = -1;
            bool bBareReply = false;
            int Result = Transact(Fd, 0, kCheckServiceTransaction, &ParcelData, &Handle, &bBareReply);
            return std::make_tuple(Result, Handle, bBareReply);
        };

        auto [Result, Handle, bBareReply] = TryOnce(NeedsHeader > 0);

        // Transact ok but no handle, bare reply: onTransact() bailed on our interface token.
        if (Result == 1 && Handle <= 0 && bBareReply && NeedsHeader == 0)
        {
            NeedsHeader = 1;
            std::tie(Result, Handle, bBareReply) = TryOnce(true);
        }
        else if (!(Result == 1 && Handle <= 0 && bBareReply))
        {
            NeedsHeader = (NeedsHeader > 0) ? 1 : -1;
        }

        return (Result == 1 && Handle > 0) ? Handle : -1;
    }

    /// @brief The /dev/binder fd + mmap + resolved service handle shared by Run() and Dump().
    struct FBinderSession
    {
        int Fd = -1;
        void *Vm = nullptr;
        int64_t Handle = -1;

        bool Open(const std::string &Service)
        {
            Fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (Fd < 0)
                return false;

            // BINDER_VERSION before mmap - matches libbinder; required on some kernels.
            binder_version Version{};
            if (ioctl(Fd, BINDER_VERSION, &Version) < 0)
                return false;

            Vm = mmap(nullptr, 128 * 1024, PROT_READ, MAP_PRIVATE, Fd, 0);
            if (Vm == MAP_FAILED)
            {
                Vm = nullptr;
                return false;
            }

            Handle = GetService(Fd, Service);
            return Handle > 0;
        }

        ~FBinderSession()
        {
            if (Vm)
                munmap(Vm, 128 * 1024);
            if (Fd >= 0)
                close(Fd);
        }
    };

    std::string ReadPipeUntilEOF(int ReadFd)
    {
        std::string Out;
        char Temp[1024];
        ssize_t NumRead;
        while ((NumRead = BS_EINTR_RETRY(read(ReadFd, Temp, sizeof(Temp)))) > 0)
            Out.append(Temp, static_cast<size_t>(NumRead));
        return Out;
    }
} // namespace

namespace BinderShell
{
    bool Run(const std::string &Service, const std::vector<std::string> &Args, std::string &OutOutput)
    {
        OutOutput.clear();

        FBinderSession Session;
        if (!Session.Open(Service))
            return false;

        int PipeFds[2];
        if (pipe(PipeFds) != 0)
            return false;
        const int ReadFd = PipeFds[0];
        int WriteFd = PipeFds[1];

        const int DevNullFd = open("/dev/null", O_RDWR);
        if (DevNullFd < 0)
        {
            close(ReadFd);
            close(WriteFd);
            return false;
        }

        // shellCommand parcel: in/out/err FDs, argc, args, two null binders.
        FParcel ParcelData;
        ParcelData.WriteFd(DevNullFd);
        ParcelData.WriteFd(WriteFd);
        ParcelData.WriteFd(WriteFd);
        ParcelData.Write32(static_cast<uint32_t>(Args.size()));
        for (const std::string &Arg : Args)
            ParcelData.WriteString16(Arg);
        ParcelData.WriteNullBinder();
        ParcelData.WriteNullBinder();

        // Drains the pipe while Transact() blocks below - a large reply would otherwise fill the
        // pipe buffer and deadlock, since the target can't finish writing until we read, and
        // Transact() can't return until the target finishes.
        std::string Drained;
        std::thread Reader([&] { Drained = ReadPipeUntilEOF(ReadFd); });

        const int Result = Transact(Session.Fd,
                                    static_cast<uint32_t>(Session.Handle),
                                    kShellCommandTransaction,
                                    &ParcelData,
                                    nullptr);

        close(WriteFd); // Lets the reader thread see EOF.
        close(DevNullFd);
        Reader.join();
        close(ReadFd);

        const bool bOk = Result == 1;
        if (bOk)
            OutOutput = std::move(Drained);

        return bOk;
    }

    bool Dump(const std::string &Service, const std::vector<std::string> &Args, std::string &OutOutput)
    {
        OutOutput.clear();

        FBinderSession Session;
        if (!Session.Open(Service))
            return false;

        int PipeFds[2];
        if (pipe(PipeFds) != 0)
            return false;
        const int ReadFd = PipeFds[0];
        int WriteFd = PipeFds[1];

        // dump() parcel: one output FD, then argc + args - no shell callback objects.
        FParcel ParcelData;
        ParcelData.WriteFd(WriteFd);
        ParcelData.Write32(static_cast<uint32_t>(Args.size()));
        for (const std::string &Arg : Args)
            ParcelData.WriteString16(Arg);

        // Drains the pipe while Transact() blocks below - dumpsys output is easily bigger than
        // the pipe buffer, which would otherwise deadlock the target against Transact() never
        // returning.
        std::string Drained;
        std::thread Reader([&] { Drained = ReadPipeUntilEOF(ReadFd); });

        const int Result = Transact(Session.Fd,
                                    static_cast<uint32_t>(Session.Handle),
                                    kDumpTransaction,
                                    &ParcelData,
                                    nullptr);

        close(WriteFd); // Lets the reader thread see EOF.
        Reader.join();
        close(ReadFd);

        const bool bOk = Result == 1;
        if (bOk)
            OutOutput = std::move(Drained);

        return bOk;
    }
} // namespace BinderShell
