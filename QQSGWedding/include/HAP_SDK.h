// ============================================================================
// HAP SDK - C/C++ Header
// ============================================================================
//
// API Documentation | 接口文档:
//     For detailed information about all available HAP client APIs,
//     please visit:
//     如需查看 HAP 客户端接口的详细说明,请访问:
//         https://16hex.cc/client/cpp
//
// Error Code Reference | 错误码说明:
//     For a full list of possible error codes returned by the SDK,
//     please refer to:
//     如需查看完整的错误码信息,请访问:
//         https://16hex.cc/error-code
//
// ============================================================================
#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef _KERNEL_MODE

#ifdef _WIN64
#pragma comment(lib, "HAP_DDK64.lib")
#else
#error "Kernel mode is only supported on x64"
#endif

#else

#ifdef _WIN64
#pragma comment(lib, "HAP_SDK64.lib")
#else
#pragma comment(lib, "HAP_SDK32.lib")
#endif
#endif

typedef
#ifdef __cplusplus
enum class UserInfoType :uint8_t
#else
enum UserInfoType
#endif
{
    License,
    Owner,
    Note,
    ExpireTime,
    Credits,
#ifdef __cplusplus
    Max
#endif
} UserInfoType;

#define DEF_HAP_CONST_USER_LICENSE volatile const char* HAP_CONST_USER_LICENSE = "HAP_CONST_USER_LICENSE__HxCE628957_6796_43ce_983B_471C3A9BDE29_CE628957_6796_43ce_983B_471C3A9BDE29x";

typedef
#ifdef __cplusplus
enum class ClientVersionInfoType :uint8_t
#else
enum ClientVersionInfoType
#endif
{
    Note_UTF8,                      // UTF8 编码备注
    Note_GBK,                       // GBK 编码备注
    Note_UTF16_LE,                  // UTF16_LE 编码备注
#ifdef __cplusplus
    Max
#endif
} ClientVersionInfoType;

// 客户端软件版本结构
typedef union ClientVersion
{
    struct
    {
        uint16_t major;				// 主版本号
        uint16_t minor;				// 次版本号
        uint16_t revision;			// 修订版本号
        uint16_t build;				// 构建版本号
    };
    uint64_t    value;		        // 版本值

#ifdef __cplusplus
    inline ClientVersion() : value(0) {}

    //inline ClientVersion(const ClientVersion& version_) : value(version_.value) {}

    inline ClientVersion(uint64_t value_) : value(value_) {}

    inline ClientVersion(uint16_t major_, uint16_t minor_, uint16_t revision_, uint16_t build_) :
        major(major_), minor(minor_), revision(revision_), build(build_) {
    }
#endif
} ClientVersion;

#define HAP_API(x) __declspec(dllimport) x __stdcall

#ifdef __cplusplus
extern "C" {
#endif

    HAP_API(int64_t) HAP_MakeVersion(uint16_t major, uint16_t minor, uint16_t revision, uint16_t build);

#ifdef __cplusplus
    HAP_API(bool) HAP_Initialize(const char* ip, int port, const ClientVersion& version);
#else
    HAP_API(bool) HAP_Initialize(const char* ip, int port, const ClientVersion* version);
#endif

    HAP_API(void) HAP_Cleanup();

    HAP_API(bool) HAP_Login(const char* key);

    HAP_API(bool) HAP_GetUserInfo(UserInfoType type, void** pvResult, size_t* pvResultLength);

    HAP_API(bool) HAP_GetClientVersionInfo(ClientVersionInfoType type, void** pvResult, size_t* pvResultLength);

    HAP_API(uint32_t) HAP_GetLastError();

    HAP_API(bool) HAP_Heartbeat();

    HAP_API(bool) HAP_LoginIntegrity();

    HAP_API(void) HAP_CloudFunction(const char* command, uint8_t** pvResult, size_t* pvResultLength);

#ifndef _KERNEL_MODE
    HAP_API(void) HAP_TerminateProcess(uint32_t exit_code);
#endif

#ifdef __cplusplus
}
#endif