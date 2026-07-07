
#include "uuid.h"

#ifdef _WIN32
    #include <rpc.h>
    #pragma comment(lib, "Rpcrt4.lib")
#elif defined(__ANDROID__)
    #include <random>
    #include <array>
    #include <sstream>
    #include <iomanip>
#else
    #include <uuid/uuid.h>
#endif

std::string cpp::utils::generate_uuid()
{
#ifdef _WIN32
    UUID uuid;
    UuidCreate(&uuid);

    RPC_CSTR str = nullptr;
    UuidToStringA(&uuid, &str);

    std::string result(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    return result;
#elif defined(__ANDROID__)
    std::array<unsigned char, 16> bytes;
    std::random_device rd;

    for (auto& b : bytes) {
        b = static_cast<unsigned char>(rd());
    }

    // RFC 4122 version 4 UUID
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    std::ostringstream ss;
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            ss << "-";

        ss << std::hex
           << std::setw(2)
           << std::setfill('0')
           << static_cast<int>(bytes[i]);
    }
    return ss.str();
#else
    uuid_t uuid;
    char str[37];
    uuid_generate(uuid);
    uuid_unparse(uuid, str);
    return std::string(str);
#endif
}