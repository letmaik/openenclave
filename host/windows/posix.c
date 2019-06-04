// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** windows/posix.c:
**
**     This file implements POSIX OCALLs for Windows. Most of these are stubs
**     which are still under development.
**
**==============================================================================
*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <sys/stat.h>
// clang-format off
#include "ws2tcpip.h"
#include "winsock2.h"
#include "windows.h"
// clang-format on

#include "posix_u.h"

#include "openenclave/corelibc/errno.h"
#include "openenclave/corelibc/fcntl.h"
#include "openenclave/corelibc/dirent.h"
#include "../hostthread.h"
#include <assert.h>

/*
**==============================================================================
**
** Shared init-once of as critical section.
**
**==============================================================================
*/

static INIT_ONCE _once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION _critical_section;

static BOOL CALLBACK
_init_once_func(PINIT_ONCE init_once, PVOID parameter, PVOID* context)
{
    OE_UNUSED(init_once);
    OE_UNUSED(parameter);
    OE_UNUSED(context);

    InitializeCriticalSectionAndSpinCount(&_critical_section, 1000);
    return TRUE;
}

static void _init_once(void)
{
    PVOID context;
    InitOnceExecuteOnce(&_once, _init_once_func, NULL, &context);
}

static void _lock(void)
{
    _init_once();
    EnterCriticalSection(&_critical_section);
}

static void _unlock(void)
{
    LeaveCriticalSection(&_critical_section);
}

/*
**==============================================================================
**
** An array of non-blocking sockets.
**
**==============================================================================
*/

#define MAX_NON_BLOCKING_SOCKETS 1024

static SOCKET _nbio_sockets[MAX_NON_BLOCKING_SOCKETS];
static size_t _num_nbio_sockets;

bool _is_nbio_socket(SOCKET sock)
{
    _lock();

    for (size_t i = 0; i < _num_nbio_sockets; i++)
    {
        if (_nbio_sockets[i] == sock)
        {
            _unlock();
            return true;
        }
    }

    _unlock();

    return false;
}

int _add_nbio_socket(SOCKET sock)
{
    _lock();

    if (_num_nbio_sockets == MAX_NON_BLOCKING_SOCKETS)
    {
        _unlock();
        return -1;
    }

    _nbio_sockets[_num_nbio_sockets++] = sock;

    _unlock();

    return 0;
}

int _remove_nbio_socket(SOCKET sock)
{
    _lock();

    for (size_t i = 0; i < _num_nbio_sockets; i++)
    {
        if (_nbio_sockets[i] == sock)
        {
            _nbio_sockets[i] = _nbio_sockets[_num_nbio_sockets - 1];
            _num_nbio_sockets--;
            _unlock();
            return 0;
        }
    }

    _unlock();

    return -1;
}

/*
**==============================================================================
**
** Errno/GetLastError conversion
**
**==============================================================================
*/

struct errno_tab_entry
{
    DWORD winerr;
    int error_no;
};

static struct errno_tab_entry errno2winerr[] = {
    {ERROR_ACCESS_DENIED, OE_EACCES},
    {ERROR_ACTIVE_CONNECTIONS, OE_EAGAIN},
    {ERROR_ALREADY_EXISTS, OE_EEXIST},
    {ERROR_BAD_DEVICE, OE_ENODEV},
    {ERROR_BAD_EXE_FORMAT, OE_ENOEXEC},
    {ERROR_BAD_NETPATH, OE_ENOENT},
    {ERROR_BAD_NET_NAME, OE_ENOENT},
    {ERROR_BAD_NET_RESP, OE_ENOSYS},
    {ERROR_BAD_PATHNAME, OE_ENOENT},
    {ERROR_BAD_PIPE, OE_EINVAL},
    {ERROR_BAD_UNIT, OE_ENODEV},
    {ERROR_BAD_USERNAME, OE_EINVAL},
    {ERROR_BEGINNING_OF_MEDIA, OE_EIO},
    {ERROR_BROKEN_PIPE, OE_EPIPE},
    {ERROR_BUSY, OE_EBUSY},
    {ERROR_BUS_RESET, OE_EIO},
    {ERROR_CALL_NOT_IMPLEMENTED, OE_ENOSYS},
    {ERROR_CANCELLED, OE_EINTR},
    {ERROR_CANNOT_MAKE, OE_EPERM},
    {ERROR_CHILD_NOT_COMPLETE, OE_EBUSY},
    {ERROR_COMMITMENT_LIMIT, OE_EAGAIN},
    {ERROR_CONNECTION_REFUSED, OE_ECONNREFUSED},
    {ERROR_CRC, OE_EIO},
    {ERROR_DEVICE_DOOR_OPEN, OE_EIO},
    {ERROR_DEVICE_IN_USE, OE_EAGAIN},
    {ERROR_DEVICE_REQUIRES_CLEANING, OE_EIO},
    {ERROR_DEV_NOT_EXIST, OE_ENOENT},
    {ERROR_DIRECTORY, OE_ENOTDIR},
    {ERROR_DIR_NOT_EMPTY, OE_ENOTEMPTY},
    {ERROR_DISK_CORRUPT, OE_EIO},
    {ERROR_DISK_FULL, OE_ENOSPC},
    {ERROR_DS_GENERIC_ERROR, OE_EIO},
    {ERROR_DUP_NAME, OE_ENOTUNIQ},
    {ERROR_EAS_DIDNT_FIT, OE_ENOSPC},
    {ERROR_EAS_NOT_SUPPORTED, OE_ENOTSUP},
    {ERROR_EA_LIST_INCONSISTENT, OE_EINVAL},
    {ERROR_EA_TABLE_FULL, OE_ENOSPC},
    {ERROR_END_OF_MEDIA, OE_ENOSPC},
    {ERROR_EOM_OVERFLOW, OE_EIO},
    {ERROR_EXE_MACHINE_TYPE_MISMATCH, OE_ENOEXEC},
    {ERROR_EXE_MARKED_INVALID, OE_ENOEXEC},
    {ERROR_FILEMARK_DETECTED, OE_EIO},
    {ERROR_FILENAME_EXCED_RANGE, OE_ENAMETOOLONG},
    {ERROR_FILE_CORRUPT, OE_EEXIST},
    {ERROR_FILE_EXISTS, OE_EEXIST},
    {ERROR_FILE_INVALID, OE_ENXIO},
    {ERROR_FILE_NOT_FOUND, OE_ENOENT},
    {ERROR_HANDLE_DISK_FULL, OE_ENOSPC},
    {ERROR_HANDLE_EOF, OE_ENODATA},
    {ERROR_INVALID_ADDRESS, OE_EINVAL},
    {ERROR_INVALID_AT_INTERRUPT_TIME, OE_EINTR},
    {ERROR_INVALID_BLOCK_LENGTH, OE_EIO},
    {ERROR_INVALID_DATA, OE_EINVAL},
    {ERROR_INVALID_DRIVE, OE_ENODEV},
    {ERROR_INVALID_EA_NAME, OE_EINVAL},
    {ERROR_INVALID_EXE_SIGNATURE, OE_ENOEXEC},
    {ERROR_INVALID_FUNCTION, OE_EBADRQC},
    {ERROR_INVALID_HANDLE, OE_EBADF},
    {ERROR_INVALID_NAME, OE_ENOENT},
    {ERROR_INVALID_PARAMETER, OE_EINVAL},
    {ERROR_INVALID_SIGNAL_NUMBER, OE_EINVAL},
    {ERROR_IOPL_NOT_ENABLED, OE_ENOEXEC},
    {ERROR_IO_DEVICE, OE_EIO},
    {ERROR_IO_INCOMPLETE, OE_EAGAIN},
    {ERROR_IO_PENDING, OE_EAGAIN},
    {ERROR_LOCK_VIOLATION, OE_EBUSY},
    {ERROR_MAX_THRDS_REACHED, OE_EAGAIN},
    {ERROR_META_EXPANSION_TOO_LONG, OE_EINVAL},
    {ERROR_MOD_NOT_FOUND, OE_ENOENT},
    {ERROR_MORE_DATA, OE_EMSGSIZE},
    {ERROR_NEGATIVE_SEEK, OE_EINVAL},
    {ERROR_NETNAME_DELETED, OE_ENOENT},
    {ERROR_NOACCESS, OE_EFAULT},
    {ERROR_NONE_MAPPED, OE_EINVAL},
    {ERROR_NONPAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_NOT_CONNECTED, OE_ENOLINK},
    {ERROR_NOT_ENOUGH_MEMORY, OE_ENOMEM},
    {ERROR_NOT_ENOUGH_QUOTA, OE_EIO},
    {ERROR_NOT_OWNER, OE_EPERM},
    {ERROR_NOT_READY, OE_ENOMEDIUM},
    {ERROR_NOT_SAME_DEVICE, OE_EXDEV},
    {ERROR_NOT_SUPPORTED, OE_ENOSYS},
    {ERROR_NO_DATA, OE_EPIPE},
    {ERROR_NO_DATA_DETECTED, OE_EIO},
    {ERROR_NO_MEDIA_IN_DRIVE, OE_ENOMEDIUM},
    {ERROR_NO_MORE_FILES, OE_ENFILE},
    {ERROR_NO_MORE_ITEMS, OE_ENFILE},
    {ERROR_NO_MORE_SEARCH_HANDLES, OE_ENFILE},
    {ERROR_NO_PROC_SLOTS, OE_EAGAIN},
    {ERROR_NO_SIGNAL_SENT, OE_EIO},
    {ERROR_NO_SYSTEM_RESOURCES, OE_EFBIG},
    {ERROR_NO_TOKEN, OE_EINVAL},
    {ERROR_OPEN_FAILED, OE_EIO},
    {ERROR_OPEN_FILES, OE_EAGAIN},
    {ERROR_OUTOFMEMORY, OE_ENOMEM},
    {ERROR_PAGED_SYSTEM_RESOURCES, OE_EAGAIN},
    {ERROR_PAGEFILE_QUOTA, OE_EAGAIN},
    {ERROR_PATH_NOT_FOUND, OE_ENOENT},
    {ERROR_PIPE_BUSY, OE_EBUSY},
    {ERROR_PIPE_CONNECTED, OE_EBUSY},
    {ERROR_PIPE_LISTENING, OE_ECOMM},
    {ERROR_PIPE_NOT_CONNECTED, OE_ECOMM},
    {ERROR_POSSIBLE_DEADLOCK, OE_EDEADLOCK},
    {ERROR_PRIVILEGE_NOT_HELD, OE_EPERM},
    {ERROR_PROCESS_ABORTED, OE_EFAULT},
    {ERROR_PROC_NOT_FOUND, OE_ESRCH},
    {ERROR_REM_NOT_LIST, OE_ENONET},
    {ERROR_SECTOR_NOT_FOUND, OE_EINVAL},
    {ERROR_SEEK, OE_EINVAL},
    {ERROR_SERVICE_REQUEST_TIMEOUT, OE_EBUSY},
    {ERROR_SETMARK_DETECTED, OE_EIO},
    {ERROR_SHARING_BUFFER_EXCEEDED, OE_ENOLCK},
    {ERROR_SHARING_VIOLATION, OE_EBUSY},
    {ERROR_SIGNAL_PENDING, OE_EBUSY},
    {ERROR_SIGNAL_REFUSED, OE_EIO},
    {ERROR_SXS_CANT_GEN_ACTCTX, OE_ELIBBAD},
    {ERROR_THREAD_1_INACTIVE, OE_EINVAL},
    {ERROR_TIMEOUT, OE_EBUSY},
    {ERROR_TOO_MANY_LINKS, OE_EMLINK},
    {ERROR_TOO_MANY_OPEN_FILES, OE_EMFILE},
    {ERROR_UNEXP_NET_ERR, OE_EIO},
    {ERROR_WAIT_NO_CHILDREN, OE_ECHILD},
    {ERROR_WORKING_SET_QUOTA, OE_EAGAIN},
    {ERROR_WRITE_PROTECT, OE_EROFS},
    {0, 0}};

static DWORD _errno_to_winerr(int errno)
{
    struct errno_tab_entry* pent = errno2winerr;

    do
    {
        if (pent->error_no == errno)
        {
            return pent->winerr;
        }
        pent++;

    } while (pent->error_no != 0);

    return ERROR_INVALID_PARAMETER;
}

static int _winerr_to_errno(DWORD winerr)
{
    struct errno_tab_entry* pent = errno2winerr;

    do
    {
        if (pent->winerr == winerr)
        {
            return pent->error_no;
        }
        pent++;

    } while (pent->winerr != 0);

    return OE_EINVAL;
}

static struct errno_tab_entry errno2winsockerr[] = {
    {WSAEINTR, OE_EINTR},
    {WSAEBADF, OE_EBADF},
    {WSAEACCES, OE_EACCES},
    {WSAEFAULT, OE_EFAULT},
    {WSAEINVAL, OE_EINVAL},
    {WSAEMFILE, OE_EMFILE},
    {WSAEWOULDBLOCK, OE_EWOULDBLOCK},
    {WSAEINPROGRESS, OE_EINPROGRESS},
    {WSAEALREADY, OE_EALREADY},
    {WSAENOTSOCK, OE_ENOTSOCK},
    {WSAEDESTADDRREQ, OE_EDESTADDRREQ},
    {WSAEMSGSIZE, OE_EMSGSIZE},
    {WSAEPROTOTYPE, OE_EPROTOTYPE},
    {WSAENOPROTOOPT, OE_ENOPROTOOPT},
    {WSAEPROTONOSUPPORT, OE_EPROTONOSUPPORT},
    {WSAESOCKTNOSUPPORT, OE_ESOCKTNOSUPPORT},
    {WSAEOPNOTSUPP, OE_EOPNOTSUPP},
    {WSAEPFNOSUPPORT, OE_EPFNOSUPPORT},
    {WSAEAFNOSUPPORT, OE_EAFNOSUPPORT},
    {WSAEADDRINUSE, OE_EADDRINUSE},
    {WSAEADDRNOTAVAIL, OE_EADDRNOTAVAIL},
    {WSAENETDOWN, OE_ENETDOWN},
    {WSAENETUNREACH, OE_ENETUNREACH},
    {WSAENETRESET, OE_ENETRESET},
    {WSAECONNABORTED, OE_ECONNABORTED},
    {WSAECONNRESET, OE_ECONNRESET},
    {WSAENOBUFS, OE_ENOBUFS},
    {WSAEISCONN, OE_EISCONN},
    {WSAENOTCONN, OE_ENOTCONN},
    {WSAESHUTDOWN, OE_ESHUTDOWN},
    {WSAETOOMANYREFS, OE_ETOOMANYREFS},
    {WSAETIMEDOUT, OE_ETIMEDOUT},
    {WSAECONNREFUSED, OE_ECONNREFUSED},
    {WSAELOOP, OE_ELOOP},
    {WSAENAMETOOLONG, OE_ENAMETOOLONG},
    {WSAEHOSTDOWN, OE_EHOSTDOWN},
    {WSAEHOSTUNREACH, OE_EHOSTUNREACH},
    {WSAENOTEMPTY, OE_ENOTEMPTY},
    {WSAEUSERS, OE_EUSERS},
    {WSAEDQUOT, OE_EDQUOT},
    {WSAESTALE, OE_ESTALE},
    {WSAEREMOTE, OE_EREMOTE},
    {WSAEDISCON, 199},
    {WSAEPROCLIM, 200},
    {WSASYSNOTREADY, 201}, // Made up number but close to adjacent
    {WSAVERNOTSUPPORTED, 202},
    {WSANOTINITIALISED, 203},
    {0, 0}};

static DWORD _errno_to_winsockerr(int errno)
{
    struct errno_tab_entry* pent = errno2winsockerr;

    do
    {
        if (pent->error_no == errno)
        {
            return pent->winerr;
        }
        pent++;

    } while (pent->error_no != 0);

    return ERROR_INVALID_PARAMETER;
}

static int _winsockerr_to_errno(DWORD winsockerr)
{
    struct errno_tab_entry* pent = errno2winsockerr;

    do
    {
        if (pent->winerr == winsockerr)
        {
            return pent->error_no;
        }
        pent++;

    } while (pent->winerr != 0);

    return OE_EINVAL;
}

// Allocates char* string which follows the expected rules for
// enclaves. Paths in the format
// <driveletter>:\<item>\<item> -> /<driveletter>/<item>/item>
// <driveletter>:/<item>/<item> -> /<driveletter>/<item>/item>
// paths without drive letter are detected and the drive added
// /<item>/<item> -> /<current driveletter>/<item>/item>
// relative paths are translated to absolute with drive letter
// returns null if the string is illegal
//
// The string  must be freed
// ATTN: we don't handle paths which start with the "\\?\" thing. don't really
// think we need them
//
char* oe_win_path_to_posix(const char* path)
{
    size_t required_size = 0;
    size_t current_dir_len = 0;
    char* current_dir = NULL;
    char* enclave_path = NULL;

    if (!path)
    {
        return NULL;
    }
    // Relative or incomplete path?

    // absolute path with drive letter.
    // we do not handle device type paths ("CON:) or double-letter paths in case
    // of really large numbers of disks (>26). If you have those, mount on
    // windows
    //
    if (isalpha(path[0]) && path[1] == ':')
    {
        // Abosolute path is drive letter
        required_size = strlen(path) + 1;
    }
    else if (path[0] == '/' || path[0] == '\\')
    {
        required_size = strlen(path) + 3; // Add a drive letter to the path
    }
    else
    {
        current_dir = _getcwd(NULL, 32767);
        current_dir_len = strlen(current_dir);

        if (isalpha(*current_dir) && (current_dir[1] == ':'))
        {
            // This is expected. We convert drive: to /drive.

            char drive_letter = *current_dir;
            *current_dir = '/';
            current_dir[1] = drive_letter;
        }
        // relative path. If the path starts with "." or ".." we accomodate
        required_size = strlen(path) + current_dir_len + 1;
    }

    enclave_path = (char*)calloc(1, required_size);

    const char* psrc = path;
    const char* plimit = path + strlen(path);
    char* pdst = enclave_path;

    if (isalpha(*psrc) && psrc[1] == ':')
    {
        *pdst++ = '/';
        *pdst++ = *psrc;
        psrc += 2;
    }
    else if (*psrc == '/')
    {
        *pdst++ = '/';
        *pdst++ = _getdrive() + 'a';
    }
    else if (*psrc == '.')
    {
        memcpy(pdst, current_dir, current_dir_len);
        if (psrc[1] == '/' || psrc[1] == '\\')
        {
            pdst += current_dir_len;
            psrc++;
        }
        else if (psrc[1] == '.' && (psrc[2] == '/' || psrc[2] == '\\'))
        {
            char* rstr = strrchr(
                current_dir, '\\'); // getcwd always returns at least '\'
            pdst += current_dir_len - (rstr - current_dir);
            // When we shortend the curdir by 1 slash, we perform the ".."
            // operation we could leave it in here, but at least sometimes this
            // will allow a path that would otherwise be too long
            psrc += 2;
        }
        else
        {
            // It is an incomplete which starts with a file which starts with .
            // so we dont increment psrc at all
            pdst += current_dir_len;
            *pdst = '/';
        }
    }
    else
    {
        // Still a relative path
        memcpy(pdst, current_dir, current_dir_len);
        pdst += current_dir_len;
        *pdst++ = '/';
    }

    // Since we have to translater slashes, use a loop rather than memcpy
    while (psrc < plimit)
    {
        if (*psrc == '\\')
        {
            *pdst = '/';
        }
        else
        {
            *pdst = *psrc;
        }
        psrc++;
        pdst++;
    }
    *pdst = '\0';

    if (current_dir)
    {
        free(current_dir);
    }
    return enclave_path;
}

// Allocates WCHAR* string which follows the expected rules for
// enclaves comminication with the host file system API. Paths in the format
// /<driveletter>/<item>/<item>  become <driveletter>:/<item>/<item>
//
// The resulting string, especially with a relative path, will probably contain
// mixed slashes. We beleive Windows handles this.
//
// Adds the string "post" to the resulting string end
//
// The string  must be freed
WCHAR* oe_posix_path_to_win(const char* path, const char* post)
{
    size_t required_size = 0;
    size_t current_dir_len = 0;
    char* current_dir = NULL;
    int pathlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    size_t postlen = MultiByteToWideChar(CP_UTF8, 0, post, -1, NULL, 0);
    if (post)
    {
        postlen = MultiByteToWideChar(CP_UTF8, 0, post, -1, NULL, 0);
    }

    WCHAR* wpath = NULL;

    if (path[0] == '/')
    {
        if (isalpha(path[1]) && path[2] == '/')
        {
            wpath =
                (WCHAR*)(calloc((pathlen + postlen + 1) * sizeof(WCHAR), 1));
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, (int)pathlen);
            if (postlen)
            {
                MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen);
            }
            WCHAR drive_letter = wpath[1];
            wpath[0] = drive_letter;
            wpath[1] = ':';
        }
        else
        {
            // Absolute path needs drive letter
            wpath =
                (WCHAR*)(calloc((pathlen + postlen + 3) * sizeof(WCHAR), 1));
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath + 2, (int)pathlen);
            if (postlen)
            {
                MultiByteToWideChar(
                    CP_UTF8, 0, post, -1, wpath + pathlen - 1, (int)postlen);
            }
            WCHAR drive_letter = _getdrive() + 'A';
            wpath[0] = drive_letter;
            wpath[1] = ':';
        }
    }
    else
    {
        // Relative path
        WCHAR* current_dir = _wgetcwd(NULL, 32767);
        if (!current_dir)
        {
            _set_errno(OE_ENOMEM);
            return NULL;
        }
        size_t current_dir_len = wcslen(current_dir);

        wpath = (WCHAR*)(calloc(
            (pathlen + current_dir_len + postlen + 1) * sizeof(WCHAR), 1));
        memcpy(wpath, current_dir, current_dir_len);
        wpath[current_dir_len] = '/';
        MultiByteToWideChar(
            CP_UTF8, 0, path, -1, wpath + current_dir_len, pathlen);
        if (postlen)
        {
            MultiByteToWideChar(
                CP_UTF8,
                0,
                path,
                -1,
                wpath + current_dir_len + pathlen - 1,
                (int)postlen);
        }

        free(current_dir);
    }
    return wpath;
}

static int _sockopt_to_winsock_opt(int level, int optname)
{
    (void)level;
    // table indexed by enclave socket opt expectations
    static const int sockopt_table[] = {
        -1,           //  0
        SO_DEBUG,     //  1
        SO_REUSEADDR, // 2
        SO_TYPE,      // 3
        SO_ERROR,     //    4
        SO_DONTROUTE, //    5
        SO_BROADCAST, //    6
        SO_SNDBUF,    //    7
        SO_RCVBUF,    //    8
        -1,           // SO_SNDBUFFORCE,   32
        -1,           // SO_RCVBUFFORCE,   33
        SO_KEEPALIVE, //    9
        SO_OOBINLINE, //    10
        -1,           // SO_NO_CHECK, //    11
        -1,           // SO_PRIORITY, //    12
        SO_LINGER,    //    13
        -1,           // SO_BSDCOMPAT, //    14
        -1,           // SO_REUSEPORT, //    15
        -1,           // SO_PASSCRED, //    16
        -1,           // SO_PEERCRED, //    17
        SO_RCVLOWAT,  //    18
        SO_SNDLOWAT,  //    19
        SO_RCVTIMEO,  //    20
        SO_SNDTIMEO,  //    21

        /* Security levels - as per NRL IPv6 - don't actually do anything */
        -1, // SO_SECURITY_AUTHENTICATION, //        22
        -1, // SO_SECURITY_ENCRYPTION_TRANSPORT, //    23
        -1, // SO_SECURITY_ENCRYPTION_NETWORK, //        24
        -1, // SO_BINDTODEVICE, //    25

        /* Socket filtering */
        -1,            // SO_ATTACH_FILTER, //    26
        -1,            // SO_DETACH_FILTER, //    27
        -1,            // SO_PEERNAME, //        28
        -1,            // SO_TIMESTAMP, //        29
        SO_ACCEPTCONN, //        30
        -1,            // SO_PEERSEC, //        31
        -1,            // 33
        -1,            // SO_PASSSEC, //        34
        -1,            // SO_TIMESTAMPNS, //        35
        -1,            // SO_MARK, //            36
        -1,            // SO_TIMESTAMPING, //        37
        -1,            // SO_PROTOCOL, //        38
        -1,            // SO_DOMAIN, //        39
        -1,            // SO_RXQ_OVFL, //             40
        -1,            // SO_WIFI_STATUS, //        41
        -1,            // SO_PEEK_OFF, //        42

        /* Instruct lower device to use last 4-bytes of skb data as FCS */
        -1, // SO_NOFCS, //        43
        -1, // SO_LOCK_FILTER, //        44
        -1, // SO_SELECT_ERR_QUEUE, //    45
        -1, // SO_BUSY_POLL, //        46
        -1, // SO_MAX_PACING_RATE, //    47
        -1, // SO_BPF_EXTENSIONS, //    48
        -1, // SO_INCOMING_CPU, //        49
        -1, // SO_ATTACH_BPF, //        50
        -1, // SO_ATTACH_REUSEPORT_CBPF, //    51
        -1, // SO_ATTACH_REUSEPORT_EBPF, //    52
        -1, // SO_CNX_ADVICE, //        53
        -1, //        54
        -1, // SO_MEMINFO, //        55
        -1, // SO_INCOMING_NAPI_ID, //    56
        -1, // SO_COOKIE, //        57
        -1, // SO_PEERGROUPS, //        59
        -1, // SO_ZEROCOPY, //        60
    };

    if (optname < 0)
        return -1;
    if (optname >= sizeof(sockopt_table) / sizeof(sockopt_table[0]))
        return -1;

    return sockopt_table[optname];
}

static int _sockoptlevel_to_winsock_optlevel(int level)
{
    switch (level)
    {
        case OE_SOL_SOCKET:
            return SOL_SOCKET;

        default:
            return -1;
    }
}

//
// windows is much poorer in file bits than unix, but they reencoded the
// corresponding bits, so we have to translate
static unsigned win_stat_to_stat(unsigned winstat)
{
    unsigned ret_stat = 0;

    if (winstat & _S_IFDIR)
    {
        ret_stat |= OE_S_IFDIR;
    }
    if (winstat & _S_IFCHR)
    {
        ret_stat |= OE_S_IFCHR;
    }
    if (winstat & _S_IFIFO)
    {
        ret_stat |= OE_S_IFIFO;
    }
    if (winstat & _S_IFREG)
    {
        ret_stat |= OE_S_IFREG;
    }
    if (winstat & _S_IREAD)
    {
        ret_stat |= OE_S_IRUSR;
    }
    if (winstat & _S_IWRITE)
    {
        ret_stat |= OE_S_IWUSR;
    }
    if (winstat & _S_IEXEC)
    {
        ret_stat |= OE_S_IXUSR;
    }

    return ret_stat;
}

/*
**==============================================================================
**
** Local definitions.
**
**==============================================================================
*/

static BOOL _winsock_inited = 0;

static BOOL _winsock_init()
{
    int ret = -1;
    static WSADATA startup_data = {0};

    // Initialize Winsock
    ret = WSAStartup(MAKEWORD(2, 2), &startup_data);
    if (ret != 0)
    {
        printf("WSAStartup failed: %d\n", ret);
        return FALSE;
    }
    return TRUE;
}

__declspec(noreturn) static void _panic(
    const char* file,
    unsigned int line,
    const char* function)
{
    fprintf(stderr, "%s(%u): %s(): panic\n", file, line, function);
    abort();
}

/*
**==============================================================================
**
** File and directory I/O:
**
**==============================================================================
*/

oe_host_fd_t oe_posix_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode)
{
    oe_host_fd_t ret = -1;

    if (strcmp(pathname, "/dev/stdin") == 0)
    {
        if ((flags & 0x00000003) != OE_O_RDONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_INPUT_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else if (strcmp(pathname, "/dev/stdout") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else if (strcmp(pathname, "/dev/stderr") == 0)
    {
        if ((flags & 0x00000003) != OE_O_WRONLY)
        {
            _set_errno(OE_EINVAL);
            goto done;
        }

        if (!DuplicateHandle(
                GetCurrentProcess(),
                GetStdHandle(STD_ERROR_HANDLE),
                GetCurrentProcess(),
                (HANDLE*)&ret,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS))
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }
    }
    else
    {
        DWORD desired_access = 0;
        DWORD share_mode = 0;
        DWORD create_dispos = OPEN_EXISTING;
        DWORD file_flags = (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_POSIX_SEMANTICS);
        WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

        if ((flags & OE_O_DIRECTORY) != 0)
        {
            file_flags |=
                FILE_FLAG_BACKUP_SEMANTICS; // This will make a directory. Not
                                            // obvious but there it is
        }

        /* Open flags are neither a bitmask nor a sequence, so switching or
         * masking don't really work. */

        if ((flags & OE_O_CREAT) != 0)
        {
            create_dispos = OPEN_ALWAYS;
        }
        else
        {
            if ((flags & OE_O_TRUNC) != 0)
            {
                create_dispos = TRUNCATE_EXISTING;
            }
            else if ((flags & OE_O_APPEND) != 0)
            {
                desired_access = FILE_APPEND_DATA;
            }
        }

        // in linux land, we can always share files for read and write unless
        // they have been opened exclusive
        share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        const int ACCESS_FLAGS = 0x3; // Covers rdonly, wronly rdwr
        switch (flags & ACCESS_FLAGS)
        {
            case OE_O_RDONLY: // 0
                desired_access |= GENERIC_READ;
                if (flags & OE_O_EXCL)
                {
                    share_mode = FILE_SHARE_WRITE;
                }
                break;

            case OE_O_WRONLY: // 1
                desired_access |= GENERIC_WRITE;
                if (flags & OE_O_EXCL)
                {
                    share_mode = FILE_SHARE_READ;
                }
                break;

            case OE_O_RDWR: // 2 or 3
                desired_access |= GENERIC_READ | GENERIC_WRITE;
                if (flags & OE_O_EXCL)
                {
                    share_mode = 0;
                }
                break;

            default:
                ret = -1;
                _set_errno(OE_EINVAL);
                goto done;
                break;
        }

        if (mode & OE_S_IRUSR)
            desired_access |= GENERIC_READ;
        if (mode & OE_S_IWUSR)
            desired_access |= GENERIC_WRITE;

        HANDLE h = CreateFileW(
            wpathname,
            desired_access,
            share_mode,
            NULL,
            create_dispos,
            file_flags,
            NULL);
        if (h == INVALID_HANDLE_VALUE)
        {
            _set_errno(_winerr_to_errno(GetLastError()));
            goto done;
        }

        ret = (oe_host_fd_t)h;

        if (wpathname)
        {
            free(wpathname);
        }
    }

done:
    return ret;
}

ssize_t oe_posix_read_ocall(oe_host_fd_t fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_returned = 0;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            fd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            _set_errno(OE_EBADF);
            goto done;

        case 2:
            _set_errno(OE_EBADF);
            goto done;

        default:
            break;
    }

    if (!ReadFile((HANDLE)fd, buf, (DWORD)count, &bytes_returned, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_returned;

done:
    return ret;
}

ssize_t oe_posix_write_ocall(oe_host_fd_t fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    DWORD bytes_written = 0;

    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            // Error. You cant write to stdin
            _set_errno(OE_EBADF);
            goto done;

        case 1:
            fd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            fd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    if (!WriteFile((HANDLE)fd, buf, (DWORD)count, &bytes_written, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (ssize_t)bytes_written;

done:
    return ret;
}

ssize_t oe_posix_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_read;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_read = oe_posix_read_ocall(fd, buf, count);
    }

    ret = size_read;

done:
    return ret;
}

ssize_t oe_posix_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_written;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        const void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_written = oe_posix_write_ocall(fd, buf, count);
    }

    ret = size_written;

done:
    return ret;
}

oe_off_t oe_posix_lseek_ocall(oe_host_fd_t fd, oe_off_t offset, int whence)
{
    ssize_t ret = -1;
    DWORD sfp_rtn = 0;
    LARGE_INTEGER new_offset = {0};

    new_offset.QuadPart = offset;
    if (!SetFilePointerEx(
            (HANDLE)fd, new_offset, (PLARGE_INTEGER)&new_offset, whence))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    ret = (oe_off_t)new_offset.QuadPart;

done:
    return ret;
}

int oe_posix_close_ocall(oe_host_fd_t fd)
{
    // Convert fd 0, 1, 2 as needed
    switch (fd)
    {
        case 0:
            fd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            fd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            fd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }
    if (!CloseHandle((HANDLE)fd))
    {
        _set_errno(OE_EINVAL);
        return -1;
    }
    return 0;
}

int oe_posix_close_socket_ocall(oe_host_fd_t sockfd)
{
    if (closesocket((SOCKET)sockfd) == SOCKET_ERROR)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        return -1;
    }

    _remove_nbio_socket(sockfd);

    return 0;
}

oe_host_fd_t oe_posix_dup_ocall(oe_host_fd_t oldfd)
{
    oe_host_fd_t ret = -1;
    oe_host_fd_t newfd = -1;
    char pibuff[1024] = {0};
    struct _WSAPROTOCOL_INFOA* pi = (struct _WSAPROTOCOL_INFOA*)pibuff;

    // Convert fd 0, 1, 2 as needed
    switch (oldfd)
    {
        case 0:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_INPUT_HANDLE);
            break;

        case 1:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_OUTPUT_HANDLE);
            break;

        case 2:
            oldfd = (oe_host_fd_t)GetStdHandle(STD_ERROR_HANDLE);
            break;

        default:
            break;
    }

    ret = WSADuplicateSocketA((SOCKET)oldfd, GetCurrentProcessId(), pi);
    if (ret < 0)
    {
        int sockerr = WSAGetLastError();

        if (sockerr != WSAENOTSOCK && sockerr != WSANOTINITIALISED)
        {
            _set_errno(_winsockerr_to_errno(WSAGetLastError()));
            goto done;
        }
    }
    else
    {
        newfd = WSASocketA(-1, -1, -1, pi, 0, 0);
        ret = newfd;
        _set_errno(0);
        goto done;
    }

    if (!DuplicateHandle(
            GetCurrentProcess(),
            (HANDLE)oldfd,
            GetCurrentProcess(),
            (HANDLE*)&ret,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    return ret;
}

struct WIN_DIR_DATA
{
    HANDLE hFind;
    WIN32_FIND_DATAW FindFileData;
    int dir_offs;
    WCHAR* pdirpath;
};

uint64_t oe_posix_opendir_ocall(const char* pathname)
{
    struct WIN_DIR_DATA* pdir =
        (struct WIN_DIR_DATA*)calloc(1, sizeof(struct WIN_DIR_DATA));
    WCHAR* wpathname = oe_posix_path_to_win(pathname, "/*");

    pdir->hFind = FindFirstFileW(wpathname, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        free(wpathname);
        free(pdir);
        return 0;
    }
    pdir->dir_offs = 0;
    pdir->pdirpath = wpathname;
    return (uint64_t)pdir;
}

int oe_posix_readdir_ocall(uint64_t dirp, struct oe_dirent* entry)
{
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    int nlen = -1;

    _set_errno(0);

    if (!dirp || !entry)
    {
        _set_errno(OE_EINVAL);
        return -1;
    }

    // Find file next doesn't return '.' because it shows up in opendir and we
    // lose it but we know it is there, so we can just return it
    if (pdir->dir_offs == 0)
    {
        entry->d_off = pdir->dir_offs++;
        entry->d_type = OE_DT_DIR;
        entry->d_reclen = sizeof(struct oe_dirent);
        entry->d_name[0] = '.';
        entry->d_name[1] = '\0';
        return 0;
    }

    if (!FindNextFileW(pdir->hFind, &pdir->FindFileData))
    {
        DWORD winerr = GetLastError();

        if (winerr == ERROR_NO_MORE_FILES)
        {
            /* Return 1 to indicate there no more entries. */
            return 1;
        }
        else
        {
            _set_errno(_winerr_to_errno(winerr));
            return -1;
        }
    }

    nlen = WideCharToMultiByte(
        CP_UTF8, 0, pdir->FindFileData.cFileName, -1, NULL, 0, NULL, NULL);
    (void)WideCharToMultiByte(
        CP_UTF8,
        0,
        pdir->FindFileData.cFileName,
        nlen,
        entry->d_name,
        sizeof(entry->d_name),
        NULL,
        NULL);

    entry->d_type = 0;
    if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        entry->d_type = OE_DT_DIR;
    }
    else if (pdir->FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        entry->d_type = OE_DT_LNK;
    }
    else
    {
        entry->d_type = OE_DT_REG;
    }

    entry->d_off = pdir->dir_offs++;
    entry->d_reclen = sizeof(struct oe_dirent);

    return 0;
}

void oe_posix_rewinddir_ocall(uint64_t dirp)
{
    DWORD err = 0;
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;
    WCHAR* wpathname = pdir->pdirpath;
    // Undo abosolute path forcing again. We do this over because we need to
    // preserve the allocation address for free.
    if (wpathname[0] == '/' && wpathname[2] == ':')
    {
        wpathname++;
    }

    FindClose(pdir->hFind);
    memset(&pdir->FindFileData, 0, sizeof(pdir->FindFileData));

    pdir->hFind = FindFirstFileW(wpathname, &pdir->FindFileData);
    if (pdir->hFind == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
    }
    pdir->dir_offs = 0;
}

int oe_posix_closedir_ocall(uint64_t dirp)
{
    struct WIN_DIR_DATA* pdir = (struct WIN_DIR_DATA*)dirp;

    if (!dirp)
    {
        return -1;
    }
    if (!FindClose(pdir->hFind))
    {
        return -1;
    }
    free(pdir->pdirpath);
    pdir->pdirpath = NULL;
    free(pdir);
    return 0;
}

int oe_posix_stat_ocall(const char* pathname, struct oe_stat* buf)
{
    int ret = -1;
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);
    struct _stat64 winstat = {0};

    ret = _wstat64(wpathname, &winstat);
    if (ret < 0)
    {
        // How do we get to  wstat's error

        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

#undef st_atime
#undef st_mtime
#undef st_ctime

    buf->st_dev = winstat.st_dev;
    buf->st_ino = winstat.st_ino;
    buf->st_mode = win_stat_to_stat(winstat.st_mode);
    buf->st_nlink = winstat.st_nlink;
    buf->st_uid = winstat.st_uid;
    buf->st_gid = winstat.st_gid;
    buf->st_rdev = winstat.st_rdev;
    buf->st_size = winstat.st_size;
    buf->st_atim.tv_sec = winstat.st_atime;
    buf->st_mtim.tv_sec = winstat.st_mtime;
    buf->st_ctim.tv_sec = winstat.st_ctime;

done:

    if (wpathname)
    {
        free(wpathname);
    }

    return ret;
}

int oe_posix_access_ocall(const char* pathname, int mode)
{
    int ret = -1;
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

    int winmode = mode & ~1; // X_OK is a noop but makes access unhappy
    ret = _waccess(wpathname, winmode);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_posix_link_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    WCHAR* woldpath = oe_posix_path_to_win(oldpath, NULL);
    WCHAR* wnewpath = oe_posix_path_to_win(newpath, NULL);

    if (!CreateHardLinkW(wnewpath, woldpath, NULL))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }
    ret = 0;

done:
    if (woldpath)
    {
        free(woldpath);
    }

    if (wnewpath)
    {
        free(wnewpath);
    }
    return ret;
}

int oe_posix_unlink_ocall(const char* pathname)
{
    int ret = -1;
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

    ret = _wunlink(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_posix_rename_ocall(const char* oldpath, const char* newpath)
{
    int ret = -1;
    WCHAR* woldpath = oe_posix_path_to_win(oldpath, NULL);
    WCHAR* wnewpath = oe_posix_path_to_win(newpath, NULL);

    ret = _wrename(woldpath, wnewpath);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (woldpath)
    {
        free(woldpath);
    }

    if (wnewpath)
    {
        free(wnewpath);
    }
    return ret;
}

int oe_posix_truncate_ocall(const char* pathname, oe_off_t length)
{
    int ret = -1;
    DWORD sfp_rtn = 0;
    LARGE_INTEGER new_offset = {0};
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

    HANDLE h = CreateFileW(
        wpathname,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    new_offset.QuadPart = length;
    if (!SetFilePointerEx(
            h, new_offset, (PLARGE_INTEGER)&new_offset, FILE_BEGIN))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    if (!SetEndOfFile(h))
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

    CloseHandle(h);

    ret = 0;

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_posix_mkdir_ocall(const char* pathname, oe_mode_t mode)
{
    int ret = -1;
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

    ret = _wmkdir(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

int oe_posix_rmdir_ocall(const char* pathname)
{
    int ret = -1;
    WCHAR* wpathname = oe_posix_path_to_win(pathname, NULL);

    ret = _wrmdir(wpathname);
    if (ret < 0)
    {
        _set_errno(_winerr_to_errno(GetLastError()));
        goto done;
    }

done:
    if (wpathname)
    {
        free(wpathname);
    }
    return ret;
}

/*
**==============================================================================
**
** Socket I/O:
**
**==============================================================================
*/

oe_host_fd_t oe_posix_socket_ocall(int domain, int type, int protocol)
{
    oe_host_fd_t ret = -1;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (!_winsock_inited)
    {
        if (!_winsock_init())
        {
            _set_errno(OE_ENOTSOCK);
        }
    }

    // We are hoping, and think it is true, that accept in winsock returns the
    // same error returns as accept everywhere else
    ret = socket(domain, type, protocol);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv_out[2])
{
    int ret = -1;
    char reuse_addr = true;
    int addrlen = 0;

    oe_host_fd_t listener = (oe_host_fd_t)INVALID_HANDLE_VALUE;

    SOCKADDR_IN addr;

    if (!_winsock_inited)
    {
        if (!_winsock_init())
        {
            _set_errno(OE_ENOTSOCK);
        }
    }

    // Windows doesn't support AF_UNIX, but it does loopback. Linux only
    // supports socketpair on unix-domain sockets. To square the circle, we
    // convert unix domain to inet loopback.
    if (domain == OE_AF_LOCAL)
    {
        domain = OE_AF_INET;
    }

    sv_out[1] = (oe_host_fd_t)INVALID_HANDLE_VALUE;
    sv_out[0] = (oe_host_fd_t)INVALID_HANDLE_VALUE;

    _set_errno(0);
    listener = socket(domain, type, protocol);
    if (listener == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (setsockopt(
            listener,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_addr,
            (socklen_t)sizeof(reuse_addr)) == -1)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (bind(listener, (struct sockaddr*)&addr, addrlen) == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (getsockname(listener, (struct sockaddr*)&addr, &addrlen) ==
        SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (listen(listener, 1) == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    sv_out[0] = socket(domain, type, protocol);
    if (sv_out[0] == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    if (connect(sv_out[0], (struct sockaddr*)&addr, sizeof(addr)) ==
        SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    sv_out[1] = accept(listener, NULL, NULL);
    if (sv_out[1] == INVALID_SOCKET)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    closesocket(listener);
    ret = 0;

done:
    if (ret < 0)
    {
        closesocket(listener);
        closesocket(sv_out[0]);
        closesocket(sv_out[1]);
        sv_out[0] = INVALID_SOCKET;
        sv_out[1] = INVALID_SOCKET;
    }

    return ret;
}

int oe_posix_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;

    SOCKADDR_IN sadd = *(PSOCKADDR_IN)addr;
    printf(
        "sock addr = %d %d %d %d\n",
        sadd.sin_addr.S_un.S_un_b.s_b1,
        sadd.sin_addr.S_un.S_un_b.s_b2,
        sadd.sin_addr.S_un.S_un_b.s_b3,
        sadd.sin_addr.S_un.S_un_b.s_b4);

    ret = connect((SOCKET)sockfd, (const struct sockaddr*)addr, (int)addrlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }
    return ret;
}

oe_host_fd_t oe_posix_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    oe_host_fd_t ret = -1;

    // We are hoping, and think it is true, that accept in winsock returns the
    // same error returns as accept everywhere else
    ret = accept((SOCKET)sockfd, (struct sockaddr*)addr, (int*)addrlen_out);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen)
{
    int ret = -1;

    ret = bind((SOCKET)sockfd, (struct sockaddr*)addr, (int)addrlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_listen_ocall(oe_host_fd_t sockfd, int backlog)
{
    int ret = -1;

    ret = listen((SOCKET)sockfd, backlog);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }
    return ret;
}

ssize_t oe_posix_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags)
{
    DWORD rslt = -1;
    DWORD recv_bytes = 0;
    WSABUF buf = {0};
    struct oe_iovec* msg_iov = (struct oe_iovec*)msg_iov_buf;

    buf.buf = (char*)&msg_iov[msg_iovlen];
    buf.len = (ULONG)(
        msg_iov_buf_size - ((size_t)msg_iovlen * sizeof(struct oe_iovec)));

    rslt = WSARecv((SOCKET)sockfd, &buf, 1, &recv_bytes, &flags, NULL, NULL);
    if (rslt == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        return -1;
    }

    *msg_controllen_out = 0;
    return recv_bytes;
}

ssize_t oe_posix_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags)
{
    DWORD rslt = -1;
    DWORD sent_bytes = 0;
    WSABUF buf = {0};
    struct oe_iovec* msg_iov = (struct oe_iovec*)msg_iov_buf;

    buf.buf = (char*)&msg_iov[msg_iovlen];
    buf.len = (ULONG)(
        msg_iov_buf_size - ((size_t)msg_iovlen * sizeof(struct oe_iovec)));

    rslt = WSASend((SOCKET)sockfd, &buf, 1, &sent_bytes, flags, NULL, NULL);
    if (rslt == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        return -1;
    }

    return sent_bytes;
}

ssize_t oe_posix_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags)
{
    ssize_t ret = -1;

    ret = recv((SOCKET)sockfd, buf, (int)len, flags);

    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_posix_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    ssize_t ret = -1;
    int fromlen = (int)addrlen_in;

    ret = recvfrom(
        (SOCKET)sockfd,
        buf,
        (int)len,
        flags,
        (struct sockaddr*)src_addr,
        &fromlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }
    if (addrlen_out)
    {
        *addrlen_out = (oe_socklen_t)fromlen;
    }

    return ret;
}

ssize_t oe_posix_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags)
{
    ssize_t ret = -1;

    ret = send((SOCKET)sockfd, buf, (int)len, flags);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_posix_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen)
{
    ssize_t ret = -1;

    ret = sendto(
        (SOCKET)sockfd,
        buf,
        (int)len,
        flags,
        (const struct sockaddr*)src_addr,
        (int)addrlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

ssize_t oe_posix_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;
    ssize_t ret = -1;
    ssize_t size_recv;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_recv = oe_posix_recv_ocall(fd, buf, count, 0);
    }

    ret = size_recv;

done:
    return ret;
}

ssize_t oe_posix_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size)
{
    ssize_t ret = -1;
    ssize_t size_sent;
    struct oe_iovec* iov = (struct oe_iovec*)iov_buf;

    OE_UNUSED(iov_buf_size);

    errno = 0;

    if ((!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
    {
        errno = EINVAL;
        goto done;
    }

    /* Handle zero data case. */
    if (!iov || iovcnt == 0)
    {
        ret = 0;
        goto done;
    }

    {
        const void* buf;
        size_t count;

        buf = &iov[iovcnt];
        count = iov_buf_size - ((size_t)iovcnt * sizeof(struct oe_iovec));

        size_sent = oe_posix_send_ocall(fd, buf, count, 0);
    }

    ret = size_sent;

done:
    return ret;
}

int oe_posix_shutdown_ocall(oe_host_fd_t sockfd, int how)
{
    int ret = -1;

    ret = shutdown((SOCKET)sockfd, how);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        ret = -1;
    }

    return ret;
}

static int _set_blocking(SOCKET sock, bool blocking)
{
    unsigned long flag = blocking ? 0 : 1;

    if (ioctlsocket(sock, FIONBIO, &flag) != 0)
        return -1;

    return 0;
}

int oe_posix_fcntl_ocall(oe_host_fd_t fd, int cmd, uint64_t arg)
{
    switch (cmd)
    {
        case OE_F_GETFL:
        {
            int flags = 0;

            if (_is_nbio_socket(fd))
                flags |= OE_O_NONBLOCK;

            return flags;
        }
        case OE_F_SETFL:
        {
            if ((arg & OE_O_NONBLOCK))
            {
                if (!_is_nbio_socket(fd) && _add_nbio_socket(fd) != 0)
                    return -1;

                if (_set_blocking(fd, false) != 0)
                    return -1;
            }
            else
            {
                _remove_nbio_socket(fd);

                if (_set_blocking(fd, true) != 0)
                    return -1;
            }

            return 0;
        }
        default:
        {
            break;
        }
    }

    return 0;
}

#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

int oe_posix_ioctl_ocall(oe_host_fd_t fd, uint64_t request, uint64_t arg)
{
    errno = 0;

    // We don't support any ioctls right now as we will have to translate the
    // codes from the enclave to be the equivelent for windows. But... no such
    // codes are currently being used So we panic to highlight the problem line
    // of code. In this way, we can see what ioctls are needed

    switch (request)
    {
        case TIOCGWINSZ:
        case TIOCSWINSZ:
            _set_errno(OE_ENOTTY);
            break;
        default:
            _set_errno(OE_EINVAL);
            break;
    }

    return -1;
}

int oe_posix_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen)
{
    int ret = -1;
    int winsock_optname = _sockopt_to_winsock_opt(level, optname);
    int winsock_optlevel = _sockoptlevel_to_winsock_optlevel(level);

    if (winsock_optname <= 0)
    {
        _set_errno(OE_EINVAL);
        return ret;
    }
    // We lose. The option values are gratutiously juggled. Have to translate
    ret = setsockopt(
        (SOCKET)sockfd, winsock_optlevel, winsock_optname, optval, optlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out)
{
    int ret = -1;
    int optlen = (int)optlen_in;

    // ATTN: I'm trusting getsockopt not to make funny here. IT may or may not.
    // If it does, we will have to translate the args.
    ret = getsockopt((SOCKET)sockfd, level, optname, optval, &optlen);
    if (ret == SOCKET_ERROR)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    *optlen_out = (oe_socklen_t)optlen;
    return ret;
}

int oe_posix_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getsockname((int)sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }
    else
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out)
{
    int ret;

    errno = 0;

    ret = getpeername((int)sockfd, (struct sockaddr*)addr, &addrlen_in);

    if (ret != -1)
    {
        if (addrlen_out)
            *addrlen_out = addrlen_in;
    }
    else
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
    }

    return ret;
}

int oe_posix_shutdown_sockets_device_ocall(oe_host_fd_t sockfd)
{
    // 2do: track all of the handles so we can be sure to close everything on
    // exit
    return 0;
}

/*
**==============================================================================
**
** Signals:
**
**==============================================================================
*/

int oe_posix_kill_ocall(int pid, int signum)
{
    if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid))
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        return -1;
    }
    return 0;
}

/*
**==============================================================================
**
** Resolver:
**
**==============================================================================
*/
#define GETADDRINFO_HANDLE_MAGIC 0xed11d13a

typedef struct _getaddrinfo_handle
{
    uint32_t magic;
    struct oe_addrinfo* res;
    struct oe_addrinfo* next;
} getaddrinfo_handle_t;

static getaddrinfo_handle_t* _cast_getaddrinfo_handle(void* handle_)
{
    getaddrinfo_handle_t* handle = (getaddrinfo_handle_t*)handle_;

    if (!handle || handle->magic != GETADDRINFO_HANDLE_MAGIC || !handle->res)
        return NULL;

    return handle;
}

int oe_posix_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle_out)
{
    int ret = OE_EAI_FAIL;
    getaddrinfo_handle_t* handle = NULL;

    _set_errno(0);

    if (handle_out)
        *handle_out = 0;

    if (!handle_out)
    {
        ret = OE_EAI_SYSTEM;
        errno = EINVAL;
        goto done;
    }

    if (!_winsock_inited)
    {
        if (!_winsock_init())
        {
            _set_errno(OE_ENOTSOCK);
        }
    }

    if (!(handle = calloc(1, sizeof(getaddrinfo_handle_t))))
    {
        ret = EAI_MEMORY;
        goto done;
    }

    struct addrinfo* paddr = NULL;
    if (getaddrinfo(node, service, (const struct addrinfo*)hints, &paddr) != 0)
    {
        goto done;
    }

    // In Windows addrinfo is volatile, so we need to deep copy here.
    // Build the info as a single allocation so its easy to free
    size_t size_required = 0;
    struct addrinfo* pwin_ai = paddr;
    for (; pwin_ai != NULL; pwin_ai = pwin_ai->ai_next)
    {
        size_required += sizeof(struct oe_addrinfo);
        if (pwin_ai->ai_canonname)
        {
            size_required += strlen(pwin_ai->ai_canonname) + 1;
        }
        if (pwin_ai->ai_addr)
        {
            // Allocates the max size for a sockaddr
            size_required += sizeof(struct oe_sockaddr_storage);
        }
    }

    if (!size_required)
    {
        // This should never happen
        handle->res = NULL;
        goto done;
    }

    handle->res = (struct oe_addrinfo*)calloc(1, size_required);

    pwin_ai = paddr;
    struct oe_addrinfo* pthis_res = handle->res;
    char* palloc = (char*)handle->res;
    for (; pwin_ai != NULL; pwin_ai = pwin_ai->ai_next)
    {
        pthis_res = (struct oe_addrinfo*)palloc;
        palloc += sizeof(struct oe_addrinfo);

        // Fields are not in the same order and sometimes not the same size;
        pthis_res->ai_flags = pwin_ai->ai_flags;
        pthis_res->ai_family = pwin_ai->ai_family;
        pthis_res->ai_socktype = pwin_ai->ai_socktype;
        pthis_res->ai_protocol = pwin_ai->ai_protocol;
        pthis_res->ai_addrlen = (oe_socklen_t)pwin_ai->ai_addrlen;
        if (pthis_res->ai_addrlen)
        {
            pthis_res->ai_addr = (struct oe_sockaddr*)palloc;
            palloc += pwin_ai->ai_addrlen;
            memcpy(pthis_res->ai_addr, pwin_ai->ai_addr, pwin_ai->ai_addrlen);
        }
        if (pwin_ai->ai_canonname)
        {
            pthis_res->ai_canonname = pwin_ai->ai_canonname;
            palloc += strlen(pwin_ai->ai_canonname) + 1;
            memcpy(
                pthis_res->ai_canonname,
                pwin_ai->ai_canonname,
                strlen(pwin_ai->ai_canonname));
        }
        if (pwin_ai->ai_next)
        {
            pthis_res->ai_next = (struct oe_addrinfo*)palloc;
        }
    }

    freeaddrinfo(paddr);

    handle->magic = GETADDRINFO_HANDLE_MAGIC;
    handle->next = handle->res;
    *handle_out = (uint64_t)handle;
    handle = NULL;

done:

    if (handle)
        free(handle);

    return ret;
}

int oe_posix_getaddrinfo_read_ocall(
    uint64_t handle_,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    _set_errno(0);

    if (!handle || !ai_flags || !ai_family || !ai_socktype || !ai_protocol ||
        !ai_addrlen || !ai_canonnamelen)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!ai_addr && ai_addrlen_in)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!ai_canonname && ai_canonnamelen_in)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (handle->next)
    {
        struct oe_addrinfo* p = handle->next;

        *ai_flags = p->ai_flags;
        *ai_family = p->ai_family;
        *ai_socktype = p->ai_socktype;
        *ai_protocol = p->ai_protocol;
        *ai_addrlen = (oe_socklen_t)p->ai_addrlen;

        if (p->ai_canonname)
            *ai_canonnamelen = strlen(p->ai_canonname) + 1;
        else
            *ai_canonnamelen = 0;

        if (*ai_addrlen > ai_addrlen_in)
        {
            _set_errno(OE_ENAMETOOLONG);
            goto done;
        }

        if (*ai_canonnamelen > ai_canonnamelen_in)
        {
            _set_errno(OE_ENAMETOOLONG);
            goto done;
        }

        memcpy(ai_addr, p->ai_addr, *ai_addrlen);

        if (p->ai_canonname)
            memcpy(ai_canonname, p->ai_canonname, *ai_canonnamelen);

        handle->next = handle->next->ai_next;

        ret = 0;
        goto done;
    }
    else
    {
        /* Done */
        ret = 1;
        goto done;
    }

done:
    return ret;
}

int oe_posix_getaddrinfo_close_ocall(uint64_t handle_)
{
    int ret = -1;
    getaddrinfo_handle_t* handle = _cast_getaddrinfo_handle((void*)handle_);

    _set_errno(0);

    if (!handle)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    free(handle->res);
    free(handle);

    ret = 0;

done:
    return ret;
}

int oe_posix_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags)
{
    errno = 0;

    return getnameinfo(
        (const struct sockaddr*)sa, salen, host, hostlen, serv, servlen, flags);
}

/*
**==============================================================================
**
** poll()
**
**==============================================================================
*/

static short _poll_events_to_windows(short events)
{
    short ret = 0;

    if (events & OE_POLLIN)
    {
        events &= ~OE_POLLIN;
        ret |= POLLIN;
    }

    if (events & OE_POLLRDNORM)
    {
        events &= ~OE_POLLRDNORM;
        ret |= POLLRDNORM;
    }

    if (events & OE_POLLRDBAND)
    {
        events &= ~OE_POLLRDBAND;
        ret |= POLLRDBAND;
    }

    if (events & OE_POLLOUT)
    {
        events &= ~OE_POLLOUT;
        ret |= POLLOUT;
    }

    if (events & OE_POLLWRNORM)
    {
        events &= ~OE_POLLWRNORM;
        ret |= POLLWRNORM;
    }

    if (events & OE_POLLERR)
    {
        events &= ~OE_POLLERR;
        ret |= POLLERR;
    }

    if (events & OE_POLLHUP)
    {
        events &= ~OE_POLLHUP;
        ret |= POLLHUP;
    }

    return ret;
}

static short _poll_events_to_posix(short events, short revents)
{
    short ret = 0;

    if (revents & POLLIN)
    {
        revents &= ~POLLIN;
        ret |= OE_POLLIN;
    }

    if (revents & POLLRDNORM)
    {
        revents &= ~POLLRDNORM;
        ret |= OE_POLLRDNORM;
    }

    if (revents & POLLRDBAND)
    {
        revents &= ~POLLRDBAND;
        ret |= OE_POLLRDBAND;
    }

    if (revents & POLLOUT)
    {
        revents &= ~POLLOUT;
        ret |= OE_POLLOUT;
    }

    if (revents & POLLWRNORM)
    {
        revents &= ~POLLWRNORM;
        ret |= OE_POLLWRNORM;
    }

    if (revents & POLLERR)
    {
        revents &= ~POLLERR;
        ret |= OE_POLLERR;
    }

    if (revents & POLLHUP)
    {
        /* If not requeted by caller, change to OE_POLLIN. */
        if (!(events & POLLHUP))
            ret |= OE_POLLIN;
        else
            ret |= OE_POLLHUP;

        revents &= ~POLLHUP;
    }

    if (revents & POLLPRI)
    {
        revents &= ~POLLPRI;
        ret |= OE_POLLPRI;
    }

    return ret;
}

int oe_posix_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout)
{
    int ret = -1;
    int n;
    WSAPOLLFD* fds = NULL;

    _set_errno(0);

    if (nfds <= 0)
    {
        _set_errno(OE_EINVAL);
        goto done;
    }

    if (!(fds = (WSAPOLLFD*)calloc(nfds, sizeof(WSAPOLLFD))))
    {
        _set_errno(OE_ENOMEM);
        goto done;
    }

    for (oe_nfds_t i = 0; i < nfds; i++)
    {
        fds[i].fd = host_fds[i].fd;
        fds[i].events = _poll_events_to_windows(host_fds[i].events);
    }

    if ((n = WSAPoll(fds, (ULONG)nfds, timeout)) <= 0)
    {
        _set_errno(_winsockerr_to_errno(WSAGetLastError()));
        goto done;
    }

    for (int i = 0; i < nfds; i++)
    {
        host_fds[i].revents =
            _poll_events_to_posix(fds[i].events, fds[i].revents);
    }

    ret = n;

done:

    if (fds)
        free(fds);

    return ret;
}

/*
**==============================================================================
**
** uid, gid, pid, and groups:
**
**==============================================================================
*/

/* You cna't make an automatic translation between windows SID and unix uid/gid.
 * Eventually you need to just return plausible dummy data. In this case, the
 * default group memberships from ubuntu 18.04
 */
static const int32_t USER_ID = 1001;
static const int32_t GROUP_ID = 1001;
static const int32_t GROUPS[] = {4, 20, 24, 25, 27, 29, 30, 44, 46, 109, 110};

int oe_posix_getpid(void)
{
    return GetCurrentProcessId();
}

// clang-format off
#include <tlhelp32.h>
// clang-format on
int oe_posix_getppid(void)
{
    int pid = -1;
    int ppid = -1;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    pid = GetCurrentProcessId();
    if (Process32First(h, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(h, &pe));
    }
    CloseHandle(h);
    return ppid;
}

int oe_posix_getpgrp(void)
{
    return 0; // Means the process group is identical to the process. Windows
              // doens't really have process groups
}

unsigned int oe_posix_getuid(void)
{
    return USER_ID;
}

unsigned int oe_posix_geteuid(void)
{
    return USER_ID;
}

unsigned int oe_posix_getgid(void)
{
    return GROUP_ID;
}

unsigned int oe_posix_getegid(void)
{
    return GROUP_ID;
}

int oe_posix_getpgid(int pid)
{
    return 0;
}

int oe_posix_getgroups(size_t size, unsigned int* list)
{
    if (size == 0)
    {
        return (int32_t)(sizeof(GROUPS) / sizeof(GROUPS[0]));
    }
    if (size < (sizeof(GROUPS) / sizeof(GROUPS[0])))
    {
        _set_errno(OE_EINVAL);
        return -1;
    }
    else
    {
        size = (sizeof(GROUPS) / sizeof(GROUPS[0]));
    }

    memcpy(list, GROUPS, sizeof(GROUPS));
    return (int32_t)size;
}

/*
**==============================================================================
**
** uname():
**
**==============================================================================
*/

int oe_posix_uname_ocall(struct oe_utsname* buf)
{
    OSVERSIONINFOW osvi;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionExW(&osvi);

    // 2do: machine
    memset(buf->sysname, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->nodename, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->release, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->version, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->machine, 0, __OE_UTSNAME_FIELD_SIZE);
    memset(buf->domainname, 0, __OE_UTSNAME_FIELD_SIZE);

    snprintf(
        buf->release,
        __OE_UTSNAME_FIELD_SIZE,
        "%d.%d",
        osvi.dwMajorVersion,
        osvi.dwMinorVersion);
    snprintf(buf->version, __OE_UTSNAME_FIELD_SIZE, "%d", osvi.dwBuildNumber);

    GetEnvironmentVariable("OS", buf->sysname, __OE_UTSNAME_FIELD_SIZE);
    GetEnvironmentVariable(
        "USERDNSDOMAIN", buf->domainname, __OE_UTSNAME_FIELD_SIZE);
    GetEnvironmentVariable(
        "COMPUTERNAME", buf->nodename, __OE_UTSNAME_FIELD_SIZE);

    return 0;
}
