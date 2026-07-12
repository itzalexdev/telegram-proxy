#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_PORT 1443
#define HANDSHAKE_SIZE 64
#define KEY_SIZE 32
#define IV_SIZE 16
#define MAX_CONNECTIONS 64
#define IO_BUFFER_SIZE 65536
#define PACKET_BUFFER_SIZE (16U * 1024U * 1024U)
#define AES_BATCH_SIZE 4096

#define PROTOCOL_ABRIDGED 0xEFEFEFEFU
#define PROTOCOL_INTERMEDIATE 0xEEEEEEEEU
#define PROTOCOL_PADDED 0xDDDDDDDDU

#define PROXY_SECRET_HEX "b277d051fec605df7f3a57badd188a1d"

static const unsigned char PROXY_SECRET[16] = {
    0xb2, 0x77, 0xd0, 0x51, 0xfe, 0xc6, 0x05, 0xdf,
    0x7f, 0x3a, 0x57, 0xba, 0xdd, 0x18, 0x8a, 0x1d
};

static volatile LONG active_connections = 0;
static volatile LONG preferred_front_index = -1;
static volatile LONG front_candidate_counter = -1;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static SRWLOCK output_lock = SRWLOCK_INIT;

static void initialize_log_file(void) {
    wchar_t path[MAX_PATH];
    const wchar_t filename[] = L"telegram-proxy.log";
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    DWORD position;
    DWORD index;
    if (length == 0 || length >= MAX_PATH) {
        return;
    }
    position = length;
    while (position > 0 && path[position - 1] != L'\\' &&
           path[position - 1] != L'/') {
        --position;
    }
    for (index = 0; filename[index] != L'\0' &&
                    position + index + 1 < MAX_PATH; ++index) {
        path[position + index] = filename[index];
    }
    path[position + index] = L'\0';
    log_file = CreateFileW(path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void *memcpy(void *destination, const void *source, size_t count) {
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    size_t index;
    for (index = 0; index < count; ++index) {
        out[index] = in[index];
    }
    return destination;
}

void *memset(void *destination, int value, size_t count) {
    unsigned char *out = (unsigned char *)destination;
    size_t index;
    for (index = 0; index < count; ++index) {
        out[index] = (unsigned char)value;
    }
    return destination;
}

void *memmove(void *destination, const void *source, size_t count) {
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    size_t index;
    if (out < in) {
        for (index = 0; index < count; ++index) {
            out[index] = in[index];
        }
    } else if (out > in) {
        for (index = count; index > 0; --index) {
            out[index - 1] = in[index - 1];
        }
    }
    return destination;
}

static int bytes_equal(const unsigned char *left,
                       const unsigned char *right, size_t count) {
    size_t index;
    unsigned char difference = 0;
    for (index = 0; index < count; ++index) {
        difference |= (unsigned char)(left[index] ^ right[index]);
    }
    return difference == 0;
}

static void write_text(const char *text) {
    DWORD written;
    DWORD length = 0;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    while (text[length] != '\0') {
        ++length;
    }
    AcquireSRWLockExclusive(&output_lock);
    WriteFile(output, text, length, &written, NULL);
    if (log_file != INVALID_HANDLE_VALUE) {
        WriteFile(log_file, text, length, &written, NULL);
    }
    ReleaseSRWLockExclusive(&output_lock);
}

static void write_number(unsigned int value) {
    char buffer[16];
    unsigned int position = 0;
    unsigned int index;
    if (value == 0) {
        write_text("0");
        return;
    }
    while (value > 0 && position < sizeof(buffer)) {
        buffer[position++] = (char)('0' + value % 10U);
        value /= 10U;
    }
    for (index = 0; index < position / 2; ++index) {
        char temporary = buffer[index];
        buffer[index] = buffer[position - index - 1];
        buffer[position - index - 1] = temporary;
    }
    buffer[position] = '\0';
    write_text(buffer);
}

static void write_wide_ascii(const wchar_t *text) {
    char buffer[128];
    DWORD length = 0;
    while (text[length] != L'\0' && length + 1U < sizeof(buffer)) {
        wchar_t value = text[length];
        buffer[length] = value <= 0x7f ? (char)value : '?';
        ++length;
    }
    buffer[length] = '\0';
    write_text(buffer);
}

static DWORD wide_byte_size(const wchar_t *text) {
    DWORD length = 0;
    while (text[length] != L'\0') {
        ++length;
    }
    return (length + 1U) * (DWORD)sizeof(wchar_t);
}

static void append_ascii(char *buffer, DWORD capacity, DWORD *position,
                         const char *text) {
    while (*text != '\0' && *position + 1U < capacity) {
        buffer[(*position)++] = *text++;
    }
    buffer[*position] = '\0';
}

static void append_number(char *buffer, DWORD capacity, DWORD *position,
                          unsigned int value) {
    char digits[16];
    unsigned int count = 0;
    if (value == 0) {
        append_ascii(buffer, capacity, position, "0");
        return;
    }
    while (value > 0 && count < sizeof(digits)) {
        digits[count++] = (char)('0' + value % 10U);
        value /= 10U;
    }
    while (count > 0 && *position + 1U < capacity) {
        buffer[(*position)++] = digits[--count];
    }
    buffer[*position] = '\0';
}

static void append_wide_ascii(char *buffer, DWORD capacity, DWORD *position,
                              const wchar_t *text) {
    while (*text != L'\0' && *position + 1U < capacity) {
        buffer[(*position)++] = *text <= 0x7f ? (char)*text : '?';
        ++text;
    }
    buffer[*position] = '\0';
}

static int wide_equals(const wchar_t *left, const wchar_t *right) {
    while (*left != L'\0' && *right != L'\0') {
        if (*left != *right) {
            return 0;
        }
        ++left;
        ++right;
    }
    return *left == *right;
}

static int parse_port(const wchar_t *text, unsigned short *port) {
    unsigned int value = 0;
    if (*text == L'\0') {
        return 0;
    }
    while (*text != L'\0') {
        if (*text < L'0' || *text > L'9') {
            return 0;
        }
        value = value * 10U + (unsigned int)(*text - L'0');
        if (value > 65535U) {
            return 0;
        }
        ++text;
    }
    if (value == 0) {
        return 0;
    }
    *port = (unsigned short)value;
    return 1;
}

static int parse_front_index(const wchar_t *text, LONG *front_index) {
    unsigned int value = 0;
    if (*text == L'\0') {
        return 0;
    }
    while (*text != L'\0') {
        if (*text < L'0' || *text > L'9') {
            return 0;
        }
        value = value * 10U + (unsigned int)(*text - L'0');
        if (value > 7U) {
            return 0;
        }
        ++text;
    }
    *front_index = (LONG)value;
    return 1;
}

static int receive_exact(SOCKET socket_value, unsigned char *buffer, int length) {
    int received = 0;
    while (received < length) {
        int result = recv(socket_value, (char *)buffer + received,
                          length - received, 0);
        if (result <= 0) {
            return 0;
        }
        received += result;
    }
    return 1;
}

static int send_all(SOCKET socket_value,
                    const unsigned char *buffer, int length) {
    int sent = 0;
    while (sent < length) {
        int result = send(socket_value, (const char *)buffer + sent,
                          length - sent, 0);
        if (result <= 0) {
            return 0;
        }
        sent += result;
    }
    return 1;
}

static uint32_t read_u32_le(const unsigned char *value) {
    return (uint32_t)value[0] |
           ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) |
           ((uint32_t)value[3] << 24);
}

static void write_u32_le(unsigned char *output, uint32_t value) {
    output[0] = (unsigned char)(value & 0xFFU);
    output[1] = (unsigned char)((value >> 8) & 0xFFU);
    output[2] = (unsigned char)((value >> 16) & 0xFFU);
    output[3] = (unsigned char)((value >> 24) & 0xFFU);
}

static void write_u64_le(unsigned char *output, uint64_t value) {
    unsigned int index;
    for (index = 0; index < 8; ++index) {
        output[index] = (unsigned char)((value >> (index * 8U)) & 0xFFU);
    }
}

typedef struct {
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_KEY_HANDLE key;
    unsigned char *key_object;
    DWORD key_object_size;
    unsigned char counter[16];
    unsigned char *batch_memory;
    unsigned char *counter_blocks;
    unsigned char *keystream;
    DWORD keystream_offset;
    DWORD keystream_size;
} AES_CTR;

static void aes_ctr_destroy(AES_CTR *context) {
    if (context->key != NULL) {
        BCryptDestroyKey(context->key);
    }
    if (context->algorithm != NULL) {
        BCryptCloseAlgorithmProvider(context->algorithm, 0);
    }
    if (context->key_object != NULL) {
        HeapFree(GetProcessHeap(), 0, context->key_object);
    }
    if (context->batch_memory != NULL) {
        HeapFree(GetProcessHeap(), 0, context->batch_memory);
    }
    memset(context, 0, sizeof(*context));
}

static int aes_ctr_init(AES_CTR *context, const unsigned char key[32],
                        const unsigned char iv[16]) {
    DWORD result_size = 0;
    NTSTATUS status;
    memset(context, 0, sizeof(*context));

    status = BCryptOpenAlgorithmProvider(&context->algorithm,
                                         BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0) {
        return 0;
    }
    status = BCryptSetProperty(context->algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                               sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status < 0) {
        aes_ctr_destroy(context);
        return 0;
    }
    status = BCryptGetProperty(context->algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&context->key_object_size,
                               sizeof(context->key_object_size),
                               &result_size, 0);
    if (status < 0 || context->key_object_size == 0) {
        aes_ctr_destroy(context);
        return 0;
    }
    context->key_object = (unsigned char *)HeapAlloc(
        GetProcessHeap(), 0, context->key_object_size);
    if (context->key_object == NULL) {
        aes_ctr_destroy(context);
        return 0;
    }
    context->batch_memory = (unsigned char *)HeapAlloc(
        GetProcessHeap(), 0, AES_BATCH_SIZE * 2U);
    if (context->batch_memory == NULL) {
        aes_ctr_destroy(context);
        return 0;
    }
    context->counter_blocks = context->batch_memory;
    context->keystream = context->batch_memory + AES_BATCH_SIZE;
    status = BCryptGenerateSymmetricKey(context->algorithm, &context->key,
                                        context->key_object,
                                        context->key_object_size,
                                        (PUCHAR)key, 32, 0);
    if (status < 0) {
        aes_ctr_destroy(context);
        return 0;
    }
    memcpy(context->counter, iv, 16);
    context->keystream_offset = 0;
    context->keystream_size = 0;
    return 1;
}

static void increment_counter(unsigned char counter[16]) {
    int index;
    for (index = 15; index >= 0; --index) {
        counter[index] = (unsigned char)(counter[index] + 1U);
        if (counter[index] != 0) {
            break;
        }
    }
}

static int aes_ctr_refill(AES_CTR *context, DWORD requested) {
    DWORD blocks = (requested + 15U) / 16U;
    DWORD input_size;
    DWORD encrypted = 0;
    DWORD block;
    if (blocks == 0) {
        blocks = 1;
    }
    if (blocks > AES_BATCH_SIZE / 16U) {
        blocks = AES_BATCH_SIZE / 16U;
    }
    input_size = blocks * 16U;
    for (block = 0; block < blocks; ++block) {
        memcpy(context->counter_blocks + block * 16U,
               context->counter, 16);
        increment_counter(context->counter);
    }
    if (BCryptEncrypt(context->key, context->counter_blocks, input_size,
                      NULL, NULL, 0, context->keystream, input_size,
                      &encrypted, 0) < 0 || encrypted != input_size) {
        return 0;
    }
    context->keystream_offset = 0;
    context->keystream_size = encrypted;
    return 1;
}

static int aes_ctr_update(AES_CTR *context, unsigned char *data, DWORD length) {
    DWORD position = 0;
    while (position < length) {
        DWORD available;
        DWORD count;
        DWORD index;
        if (context->keystream_offset == context->keystream_size) {
            if (!aes_ctr_refill(context, length - position)) {
                return 0;
            }
        }
        available = context->keystream_size - context->keystream_offset;
        count = length - position;
        if (count > available) {
            count = available;
        }
        for (index = 0; index < count; ++index) {
            data[position + index] ^=
                context->keystream[context->keystream_offset + index];
        }
        context->keystream_offset += count;
        position += count;
    }
    return 1;
}

static int sha256(const unsigned char *data, DWORD length,
                  unsigned char output[32]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char *hash_object = NULL;
    DWORD object_size = 0;
    DWORD result_size = 0;
    int success = 0;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                    NULL, 0) < 0) {
        goto cleanup;
    }
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&object_size, sizeof(object_size),
                          &result_size, 0) < 0 || object_size == 0) {
        goto cleanup;
    }
    hash_object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, object_size);
    if (hash_object == NULL) {
        goto cleanup;
    }
    if (BCryptCreateHash(algorithm, &hash, hash_object, object_size,
                         NULL, 0, 0) < 0) {
        goto cleanup;
    }
    if (BCryptHashData(hash, (PUCHAR)data, length, 0) < 0) {
        goto cleanup;
    }
    if (BCryptFinishHash(hash, output, 32, 0) < 0) {
        goto cleanup;
    }
    success = 1;

cleanup:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (hash_object != NULL) {
        HeapFree(GetProcessHeap(), 0, hash_object);
    }
    return success;
}

static int derive_secret_key(const unsigned char prekey[32],
                             unsigned char output[32]) {
    unsigned char material[48];
    memcpy(material, prekey, 32);
    memcpy(material + 32, PROXY_SECRET, 16);
    return sha256(material, sizeof(material), output);
}

static int random_bytes(unsigned char *buffer, DWORD length) {
    return BCryptGenRandom(NULL, buffer, length,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

typedef struct {
    AES_CTR client_decrypt;
    AES_CTR client_encrypt;
    AES_CTR telegram_encrypt;
    AES_CTR telegram_decrypt;
    uint32_t protocol;
    int dc;
    int media;
} CRYPTO_STATE;

static void crypto_state_destroy(CRYPTO_STATE *state) {
    aes_ctr_destroy(&state->client_decrypt);
    aes_ctr_destroy(&state->client_encrypt);
    aes_ctr_destroy(&state->telegram_encrypt);
    aes_ctr_destroy(&state->telegram_decrypt);
    memset(state, 0, sizeof(*state));
}

static int valid_protocol(uint32_t protocol) {
    return protocol == PROTOCOL_ABRIDGED ||
           protocol == PROTOCOL_INTERMEDIATE ||
           protocol == PROTOCOL_PADDED;
}

static int parse_client_init(const unsigned char init[64],
                             CRYPTO_STATE *state) {
    unsigned char key[32];
    unsigned char reversed[48];
    unsigned char plain[64];
    unsigned char zeroes[64];
    AES_CTR temporary;
    uint32_t protocol;
    int16_t dc_index;
    int index;

    memset(state, 0, sizeof(*state));
    memset(&temporary, 0, sizeof(temporary));
    memset(zeroes, 0, sizeof(zeroes));

    if (!derive_secret_key(init + 8, key) ||
        !aes_ctr_init(&temporary, key, init + 40)) {
        return 0;
    }
    memcpy(plain, init, 64);
    if (!aes_ctr_update(&temporary, plain, 64)) {
        aes_ctr_destroy(&temporary);
        return 0;
    }
    aes_ctr_destroy(&temporary);

    protocol = read_u32_le(plain + 56);
    if (!valid_protocol(protocol)) {
        return 0;
    }
    dc_index = (int16_t)((uint16_t)plain[60] |
                         ((uint16_t)plain[61] << 8));
    state->media = dc_index < 0;
    state->dc = dc_index < 0 ? -dc_index : dc_index;
    if (!((state->dc >= 1 && state->dc <= 5) || state->dc == 203)) {
        return 0;
    }
    state->protocol = protocol;

    if (!derive_secret_key(init + 8, key) ||
        !aes_ctr_init(&state->client_decrypt, key, init + 40)) {
        crypto_state_destroy(state);
        return 0;
    }
    if (!aes_ctr_update(&state->client_decrypt, zeroes, 64)) {
        crypto_state_destroy(state);
        return 0;
    }

    for (index = 0; index < 48; ++index) {
        reversed[index] = init[55 - index];
    }
    if (!derive_secret_key(reversed, key) ||
        !aes_ctr_init(&state->client_encrypt, key, reversed + 32)) {
        crypto_state_destroy(state);
        return 0;
    }
    return 1;
}

static int init_is_reserved(const unsigned char init[64]) {
    uint32_t first = read_u32_le(init);
    uint32_t second = read_u32_le(init + 4);
    if (init[0] == 0xEF || second == 0) {
        return 1;
    }
    return first == 0x44414548U || first == 0x54534F50U ||
           first == 0x20544547U || first == 0x4954504FU ||
           first == 0x02010316U || first == PROTOCOL_PADDED ||
           first == PROTOCOL_INTERMEDIATE;
}

static int build_obfuscated_init(uint32_t protocol, int dc_index,
                                 int use_secret,
                                 unsigned char output[64]) {
    unsigned char plain[64];
    unsigned char encrypted[64];
    unsigned char key[32];
    AES_CTR cipher;
    memset(&cipher, 0, sizeof(cipher));

    do {
        if (!random_bytes(plain, 64)) {
            return 0;
        }
    } while (init_is_reserved(plain));

    plain[56] = (unsigned char)(protocol & 0xFFU);
    plain[57] = (unsigned char)((protocol >> 8) & 0xFFU);
    plain[58] = (unsigned char)((protocol >> 16) & 0xFFU);
    plain[59] = (unsigned char)((protocol >> 24) & 0xFFU);
    plain[60] = (unsigned char)((uint16_t)dc_index & 0xFFU);
    plain[61] = (unsigned char)(((uint16_t)dc_index >> 8) & 0xFFU);

    if (use_secret) {
        if (!derive_secret_key(plain + 8, key)) {
            return 0;
        }
    } else {
        memcpy(key, plain + 8, 32);
    }
    if (!aes_ctr_init(&cipher, key, plain + 40)) {
        return 0;
    }
    memcpy(encrypted, plain, 64);
    if (!aes_ctr_update(&cipher, encrypted, 64)) {
        aes_ctr_destroy(&cipher);
        return 0;
    }
    aes_ctr_destroy(&cipher);

    memcpy(output, plain, 56);
    memcpy(output + 56, encrypted + 56, 8);
    return 1;
}

static int build_relay_init(CRYPTO_STATE *state,
                            unsigned char relay_init[64]) {
    unsigned char reversed[48];
    unsigned char zeroes[64];
    int dc_index = state->media ? -state->dc : state->dc;
    int index;
    memset(zeroes, 0, sizeof(zeroes));

    if (!build_obfuscated_init(state->protocol, dc_index, 0, relay_init)) {
        return 0;
    }
    if (!aes_ctr_init(&state->telegram_encrypt,
                      relay_init + 8, relay_init + 40) ||
        !aes_ctr_update(&state->telegram_encrypt, zeroes, 64)) {
        crypto_state_destroy(state);
        return 0;
    }
    for (index = 0; index < 48; ++index) {
        reversed[index] = relay_init[55 - index];
    }
    if (!aes_ctr_init(&state->telegram_decrypt,
                      reversed, reversed + 32)) {
        crypto_state_destroy(state);
        return 0;
    }
    return 1;
}

typedef struct {
    HINTERNET session;
    HINTERNET connection;
    HINTERNET websocket;
    int route;
    int front_index;
    int from_pool;
} WSS_CONNECTION;

#define WSS_ROUTE_DIRECT 1
#define WSS_ROUTE_FRONT 2
#define WSS_ROUTE_REDIRECT 3

static const wchar_t *CF_FRONT_DOMAINS[] = {
    L"pclead.co.uk",
    L"offshor.co.uk",
    L"cakeisalie.co.uk",
    L"noskomnadzor.co.uk",
    L"lovetrue.co.uk",
    L"sorokdva.co.uk",
    L"kartoshka.co.uk",
    L"fixtelega.co.uk"
};

static void wss_close(WSS_CONNECTION *connection) {
    if (connection->websocket != NULL) {
        WinHttpWebSocketClose(connection->websocket,
                              WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                              NULL, 0);
        WinHttpCloseHandle(connection->websocket);
    }
    if (connection->connection != NULL) {
        WinHttpCloseHandle(connection->connection);
    }
    if (connection->session != NULL) {
        WinHttpCloseHandle(connection->session);
    }
    memset(connection, 0, sizeof(*connection));
}

static void format_ws_domain(int dc, int alternate, wchar_t output[40]) {
    const wchar_t prefix[] = L"kws";
    const wchar_t suffix[] = L".web.telegram.org";
    unsigned int position = 0;
    unsigned int index;
    if (dc == 203) {
        dc = 2;
    }
    for (index = 0; prefix[index] != L'\0'; ++index) {
        output[position++] = prefix[index];
    }
    output[position++] = (wchar_t)(L'0' + dc);
    if (alternate) {
        output[position++] = L'-';
        output[position++] = L'1';
    }
    for (index = 0; suffix[index] != L'\0'; ++index) {
        output[position++] = suffix[index];
    }
    output[position] = L'\0';
}

static void format_front_domain(int dc, const wchar_t *base,
                                wchar_t output[80]) {
    const wchar_t prefix[] = L"kws";
    unsigned int position = 0;
    unsigned int index;
    if (dc == 203) {
        dc = 2;
    }
    for (index = 0; prefix[index] != L'\0'; ++index) {
        output[position++] = prefix[index];
    }
    output[position++] = (wchar_t)(L'0' + dc);
    output[position++] = L'.';
    for (index = 0; base[index] != L'\0' && position < 79; ++index) {
        output[position++] = base[index];
    }
    output[position] = L'\0';
}

static int wss_connect_domain_resolved(const wchar_t *domain,
                                       const wchar_t *resolution_hostname,
                                       WSS_CONNECTION *result) {
    HINTERNET request = NULL;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    DWORD protocols = WINHTTP_PROTOCOL_FLAG_HTTP2;
    memset(result, 0, sizeof(*result));
    result->front_index = -1;

    result->session = WinHttpOpen(L"TelegramProxy/1.0",
                                  WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (result->session == NULL) {
        goto failure;
    }
    WinHttpSetTimeouts(result->session, 5000, 5000, 5000, 10000);
    WinHttpSetOption(result->session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                     &protocols, sizeof(protocols));

    result->connection = WinHttpConnect(result->session, domain,
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (result->connection == NULL) {
        goto failure;
    }
    request = WinHttpOpenRequest(result->connection, L"GET", L"/apiws",
                                 NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (request == NULL) {
        goto failure;
    }
    if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                          NULL, 0)) {
        goto failure;
    }
    if (resolution_hostname != NULL &&
        !WinHttpSetOption(request, WINHTTP_OPTION_RESOLUTION_HOSTNAME,
                          (void *)resolution_hostname,
                          wide_byte_size(resolution_hostname))) {
        goto failure;
    }
    WinHttpAddRequestHeaders(request,
                             L"Sec-WebSocket-Protocol: binary\r\n",
                             (DWORD)-1L,
                             WINHTTP_ADDREQ_FLAG_ADD |
                             WINHTTP_ADDREQ_FLAG_REPLACE);
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        goto failure;
    }
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE |
                             WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status_code, &status_size,
                             WINHTTP_NO_HEADER_INDEX) ||
        status_code != 101) {
        goto failure;
    }
    result->websocket = WinHttpWebSocketCompleteUpgrade(request, 0);
    WinHttpCloseHandle(request);
    request = NULL;
    if (result->websocket == NULL) {
        goto failure;
    }
    return 1;

failure:
    if (request != NULL) {
        WinHttpCloseHandle(request);
    }
    wss_close(result);
    return 0;
}

static int wss_connect_domain(const wchar_t *domain,
                              WSS_CONNECTION *result) {
    return wss_connect_domain_resolved(domain, NULL, result);
}

static int wss_connect_redirect_only(int dc, int media,
                                     WSS_CONNECTION *result) {
    wchar_t domain[40];
    int first_alternate = media ? 1 : 0;
    if (dc != 2 && dc != 4 && dc != 203) {
        return 0;
    }
    format_ws_domain(dc, first_alternate, domain);
    if (wss_connect_domain_resolved(domain, L"149.154.167.220", result)) {
        result->route = WSS_ROUTE_REDIRECT;
        return 1;
    }
    format_ws_domain(dc, !first_alternate, domain);
    if (wss_connect_domain_resolved(domain, L"149.154.167.220", result)) {
        result->route = WSS_ROUTE_REDIRECT;
        return 1;
    }
    return 0;
}

static int wss_connect_new(int dc, int media, WSS_CONNECTION *result) {
    wchar_t domain[40];
    wchar_t front_domain[80];
    int first_alternate = media ? 1 : 0;
    unsigned int index;
    unsigned int attempt;
    unsigned int front_count =
        sizeof(CF_FRONT_DOMAINS) / sizeof(CF_FRONT_DOMAINS[0]);
    unsigned int start_index = 0;
    LONG preferred = InterlockedCompareExchange(&preferred_front_index,
                                                 -1, -1);

    if (wss_connect_redirect_only(dc, media, result)) {
        return 1;
    }

    if (preferred >= 0 &&
        (unsigned int)preferred < front_count) {
        format_front_domain(dc, CF_FRONT_DOMAINS[preferred], front_domain);
        if (wss_connect_domain(front_domain, result)) {
            result->route = WSS_ROUTE_FRONT;
            result->front_index = (int)preferred;
            return 1;
        }
        InterlockedCompareExchange(&preferred_front_index, -1, preferred);
    }

    start_index = (unsigned int)InterlockedIncrement(
        &front_candidate_counter) % front_count;

    for (attempt = 0; attempt < front_count; ++attempt) {
        index = (start_index + attempt) % front_count;
        if ((LONG)index == preferred) {
            continue;
        }
        format_front_domain(dc, CF_FRONT_DOMAINS[index], front_domain);
        if (wss_connect_domain(front_domain, result)) {
            result->route = WSS_ROUTE_FRONT;
            result->front_index = (int)index;
            InterlockedCompareExchange(&preferred_front_index,
                                       (LONG)index, -1);
            return 1;
        }
    }

    format_ws_domain(dc, first_alternate, domain);
    if (wss_connect_domain(domain, result)) {
        result->route = WSS_ROUTE_DIRECT;
        return 1;
    }
    format_ws_domain(dc, !first_alternate, domain);
    if (wss_connect_domain(domain, result)) {
        result->route = WSS_ROUTE_DIRECT;
        return 1;
    }
    return 0;
}

static int wss_connect_front_only(int dc, WSS_CONNECTION *result) {
    wchar_t domain[80];
    unsigned int index;
    for (index = 0;
         index < sizeof(CF_FRONT_DOMAINS) / sizeof(CF_FRONT_DOMAINS[0]);
         ++index) {
        format_front_domain(dc, CF_FRONT_DOMAINS[index], domain);
        if (wss_connect_domain(domain, result)) {
            result->route = WSS_ROUTE_FRONT;
            result->front_index = (int)index;
            return 1;
        }
    }
    return 0;
}

#define WSS_POOL_BUCKET_COUNT 4
#define WSS_POOL_SIZE 4
#define WSS_POOL_MAX_AGE_MS 100000ULL

typedef struct {
    WSS_CONNECTION entries[WSS_POOL_SIZE];
    ULONGLONG created[WSS_POOL_SIZE];
    unsigned int count;
} WSS_POOL_BUCKET;

typedef struct {
    int bucket;
    int dc;
    int media;
} WSS_POOL_WORK;

static SRWLOCK wss_pool_lock = SRWLOCK_INIT;
static WSS_POOL_BUCKET wss_pool[WSS_POOL_BUCKET_COUNT];
static volatile LONG wss_pool_started = 0;

static int wss_pool_bucket_index(int dc, int media) {
    if (dc == 2 || dc == 203) {
        return media ? 1 : 0;
    }
    if (dc == 4) {
        return media ? 3 : 2;
    }
    return -1;
}

static DWORD WINAPI wss_pool_refill_worker(void *parameter) {
    WSS_POOL_WORK *work = (WSS_POOL_WORK *)parameter;
    WSS_CONNECTION connection;
    int keep = 0;
    memset(&connection, 0, sizeof(connection));
    if (wss_connect_redirect_only(work->dc, work->media, &connection)) {
        AcquireSRWLockExclusive(&wss_pool_lock);
        if (wss_pool[work->bucket].count < WSS_POOL_SIZE) {
            unsigned int slot = wss_pool[work->bucket].count++;
            wss_pool[work->bucket].entries[slot] = connection;
            wss_pool[work->bucket].created[slot] = GetTickCount64();
            memset(&connection, 0, sizeof(connection));
            keep = 1;
        }
        ReleaseSRWLockExclusive(&wss_pool_lock);
    }
    if (!keep) {
        wss_close(&connection);
    }
    HeapFree(GetProcessHeap(), 0, work);
    return 0;
}

static void wss_pool_schedule_refill(int bucket, int dc, int media) {
    WSS_POOL_WORK *work = (WSS_POOL_WORK *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WSS_POOL_WORK));
    HANDLE thread;
    if (work == NULL) {
        return;
    }
    work->bucket = bucket;
    work->dc = dc;
    work->media = media;
    thread = CreateThread(NULL, 0, wss_pool_refill_worker, work, 0, NULL);
    if (thread == NULL) {
        HeapFree(GetProcessHeap(), 0, work);
        return;
    }
    CloseHandle(thread);
}

static void wss_pool_start(void) {
    int bucket;
    int slot;
    if (InterlockedCompareExchange(&wss_pool_started, 1, 0) != 0) {
        return;
    }
    for (bucket = 0; bucket < WSS_POOL_BUCKET_COUNT; ++bucket) {
        int dc = bucket < 2 ? 2 : 4;
        int media = bucket & 1;
        for (slot = 0; slot < WSS_POOL_SIZE; ++slot) {
            wss_pool_schedule_refill(bucket, dc, media);
        }
    }
}

static void wss_pool_wait_ready(DWORD timeout_ms) {
    ULONGLONG deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        int bucket;
        int ready = 1;
        AcquireSRWLockShared(&wss_pool_lock);
        for (bucket = 0; bucket < WSS_POOL_BUCKET_COUNT; ++bucket) {
            if (wss_pool[bucket].count == 0) {
                ready = 0;
                break;
            }
        }
        ReleaseSRWLockShared(&wss_pool_lock);
        if (ready || GetTickCount64() >= deadline) {
            return;
        }
        Sleep(25);
    }
}

static int wss_pool_take(int dc, int media, WSS_CONNECTION *result) {
    int bucket = wss_pool_bucket_index(dc, media);
    if (bucket < 0 ||
        InterlockedCompareExchange(&wss_pool_started, 0, 0) == 0) {
        return 0;
    }
    for (;;) {
        WSS_CONNECTION candidate;
        ULONGLONG created;
        unsigned int slot;
        memset(&candidate, 0, sizeof(candidate));
        AcquireSRWLockExclusive(&wss_pool_lock);
        if (wss_pool[bucket].count == 0) {
            ReleaseSRWLockExclusive(&wss_pool_lock);
            return 0;
        }
        slot = --wss_pool[bucket].count;
        candidate = wss_pool[bucket].entries[slot];
        created = wss_pool[bucket].created[slot];
        memset(&wss_pool[bucket].entries[slot], 0,
               sizeof(WSS_CONNECTION));
        ReleaseSRWLockExclusive(&wss_pool_lock);
        wss_pool_schedule_refill(bucket, dc == 203 ? 2 : dc, media);
        if (GetTickCount64() - created <= WSS_POOL_MAX_AGE_MS) {
            candidate.from_pool = 1;
            *result = candidate;
            return 1;
        }
        wss_close(&candidate);
    }
}

static int wss_connect(int dc, int media, WSS_CONNECTION *result) {
    if (wss_pool_take(dc, media, result)) {
        return 1;
    }
    return wss_connect_new(dc, media, result);
}

static int run_front_benchmark(void) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    unsigned int index;
    unsigned int best_index = 0;
    unsigned int best_ms = 0xffffffffU;
    int found = 0;

    if (!QueryPerformanceFrequency(&frequency)) {
        write_text("[front-bench] High-resolution timer unavailable.\r\n");
        return 0;
    }
    write_text("[front-bench] Telegram DC2 connection latency:\r\n");
    for (index = 0;
         index < sizeof(CF_FRONT_DOMAINS) / sizeof(CF_FRONT_DOMAINS[0]);
         ++index) {
        wchar_t domain[80];
        WSS_CONNECTION connection;
        uint64_t ticks;
        unsigned int milliseconds;
        memset(&connection, 0, sizeof(connection));
        format_front_domain(2, CF_FRONT_DOMAINS[index], domain);
        QueryPerformanceCounter(&start);
        if (!wss_connect_domain(domain, &connection)) {
            write_text("  ");
            write_wide_ascii(CF_FRONT_DOMAINS[index]);
            write_text(": FAILED\r\n");
            continue;
        }
        QueryPerformanceCounter(&end);
        ticks = (uint64_t)(end.QuadPart - start.QuadPart) * 1000ULL;
        milliseconds = (unsigned int)(ticks / (uint64_t)frequency.QuadPart);
        write_text("  ");
        write_wide_ascii(CF_FRONT_DOMAINS[index]);
        write_text(": ");
        write_number(milliseconds);
        write_text(" ms\r\n");
        if (milliseconds < best_ms) {
            best_ms = milliseconds;
            best_index = index;
            found = 1;
        }
        wss_close(&connection);
    }
    if (!found) {
        write_text("[front-bench] No working route.\r\n");
        return 0;
    }
    InterlockedExchange(&preferred_front_index, (LONG)best_index);
    write_text("[front-bench] Fastest: ");
    write_wide_ascii(CF_FRONT_DOMAINS[best_index]);
    write_text(" (");
    write_number(best_ms);
    write_text(" ms)\r\n");
    return 1;
}

static int run_front_selector(void) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    unsigned int index;
    unsigned int best_index = 0;
    uint64_t best_ticks = ~(uint64_t)0;
    int found = 0;

    if (!QueryPerformanceFrequency(&frequency)) {
        return 0;
    }
    for (index = 0;
         index < sizeof(CF_FRONT_DOMAINS) / sizeof(CF_FRONT_DOMAINS[0]);
         ++index) {
        wchar_t domain[80];
        WSS_CONNECTION connection;
        uint64_t ticks;
        memset(&connection, 0, sizeof(connection));
        format_front_domain(2, CF_FRONT_DOMAINS[index], domain);
        QueryPerformanceCounter(&start);
        if (!wss_connect_domain(domain, &connection)) {
            continue;
        }
        QueryPerformanceCounter(&end);
        ticks = (uint64_t)(end.QuadPart - start.QuadPart);
        if (ticks < best_ticks) {
            best_ticks = ticks;
            best_index = index;
            found = 1;
        }
        wss_close(&connection);
    }
    if (!found) {
        return 0;
    }
    write_number(best_index);
    write_text("\r\n");
    return 1;
}

static int wss_send(WSS_CONNECTION *connection,
                    const unsigned char *data, DWORD length) {
    return WinHttpWebSocketSend(
        connection->websocket,
        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
        (void *)data, length) == ERROR_SUCCESS;
}

typedef struct {
    unsigned char *plain;
    unsigned char *cipher;
    DWORD length;
    DWORD capacity;
    uint32_t protocol;
} PACKET_BUFFER;

static int packet_buffer_init(PACKET_BUFFER *buffer, uint32_t protocol) {
    memset(buffer, 0, sizeof(*buffer));
    buffer->capacity = PACKET_BUFFER_SIZE;
    buffer->protocol = protocol;
    buffer->plain = (unsigned char *)HeapAlloc(GetProcessHeap(), 0,
                                               buffer->capacity);
    buffer->cipher = (unsigned char *)HeapAlloc(GetProcessHeap(), 0,
                                                buffer->capacity);
    if (buffer->plain == NULL || buffer->cipher == NULL) {
        if (buffer->plain != NULL) {
            HeapFree(GetProcessHeap(), 0, buffer->plain);
        }
        if (buffer->cipher != NULL) {
            HeapFree(GetProcessHeap(), 0, buffer->cipher);
        }
        memset(buffer, 0, sizeof(*buffer));
        return 0;
    }
    return 1;
}

static void packet_buffer_destroy(PACKET_BUFFER *buffer) {
    if (buffer->plain != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer->plain);
    }
    if (buffer->cipher != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer->cipher);
    }
    memset(buffer, 0, sizeof(*buffer));
}

static int next_packet_length(const PACKET_BUFFER *buffer, DWORD *packet_size) {
    DWORD payload_size;
    DWORD header_size;
    if (buffer->length == 0) {
        return 0;
    }
    if (buffer->protocol == PROTOCOL_ABRIDGED) {
        unsigned char first = buffer->plain[0];
        if (first == 0x7F || first == 0xFF) {
            if (buffer->length < 4) {
                return 0;
            }
            payload_size = ((DWORD)buffer->plain[1] |
                            ((DWORD)buffer->plain[2] << 8) |
                            ((DWORD)buffer->plain[3] << 16)) * 4U;
            header_size = 4;
        } else {
            payload_size = (DWORD)(first & 0x7FU) * 4U;
            header_size = 1;
        }
    } else {
        if (buffer->length < 4) {
            return 0;
        }
        payload_size = read_u32_le(buffer->plain) & 0x7FFFFFFFU;
        header_size = 4;
    }
    if (payload_size == 0 || payload_size > buffer->capacity - header_size) {
        return -1;
    }
    *packet_size = header_size + payload_size;
    return buffer->length >= *packet_size ? 1 : 0;
}

typedef struct {
    SOCKET client;
    WSS_CONNECTION wss;
    CRYPTO_STATE crypto;
    volatile LONG stop;
} CONNECTION;

static DWORD WINAPI upload_thread(void *parameter) {
    CONNECTION *connection = (CONNECTION *)parameter;
    unsigned char *input = NULL;
    PACKET_BUFFER packets;
    int running = 1;
    memset(&packets, 0, sizeof(packets));

    input = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, IO_BUFFER_SIZE);
    if (input == NULL ||
        !packet_buffer_init(&packets, connection->crypto.protocol)) {
        running = 0;
    }

    while (running && InterlockedCompareExchange(&connection->stop, 0, 0) == 0) {
        int received = recv(connection->client, (char *)input,
                            IO_BUFFER_SIZE, 0);
        DWORD packet_size;
        int packet_status;
        if (received <= 0 ||
            packets.length + (DWORD)received > packets.capacity) {
            break;
        }

        memcpy(packets.plain + packets.length, input, (DWORD)received);
        if (!aes_ctr_update(&connection->crypto.client_decrypt,
                            packets.plain + packets.length,
                            (DWORD)received)) {
            break;
        }
        memcpy(packets.cipher + packets.length,
               packets.plain + packets.length, (DWORD)received);
        if (!aes_ctr_update(&connection->crypto.telegram_encrypt,
                            packets.cipher + packets.length,
                            (DWORD)received)) {
            break;
        }
        packets.length += (DWORD)received;

        for (;;) {
            packet_status = next_packet_length(&packets, &packet_size);
            if (packet_status == 0) {
                break;
            }
            if (packet_status < 0 ||
                !wss_send(&connection->wss, packets.cipher, packet_size)) {
                running = 0;
                break;
            }
            packets.length -= packet_size;
            if (packets.length > 0) {
                memmove(packets.plain, packets.plain + packet_size,
                        packets.length);
                memmove(packets.cipher, packets.cipher + packet_size,
                        packets.length);
            }
        }
    }

    InterlockedExchange(&connection->stop, 1);
    shutdown(connection->client, SD_BOTH);
    if (connection->wss.websocket != NULL) {
        WinHttpWebSocketClose(connection->wss.websocket,
                              WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                              NULL, 0);
    }
    if (input != NULL) {
        HeapFree(GetProcessHeap(), 0, input);
    }
    packet_buffer_destroy(&packets);
    return 0;
}

static void download_loop(CONNECTION *connection) {
    unsigned char *buffer = (unsigned char *)HeapAlloc(
        GetProcessHeap(), 0, IO_BUFFER_SIZE);
    if (buffer == NULL) {
        return;
    }

    while (InterlockedCompareExchange(&connection->stop, 0, 0) == 0) {
        DWORD received = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        DWORD status = WinHttpWebSocketReceive(connection->wss.websocket,
                                                buffer, IO_BUFFER_SIZE,
                                                &received, &type);
        if (status != ERROR_SUCCESS ||
            type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            break;
        }
        if (received == 0) {
            continue;
        }
        if (type != WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE &&
            type != WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            continue;
        }
        if (!aes_ctr_update(&connection->crypto.telegram_decrypt,
                            buffer, received) ||
            !aes_ctr_update(&connection->crypto.client_encrypt,
                            buffer, received) ||
            !send_all(connection->client, buffer, (int)received)) {
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, buffer);
}

static DWORD WINAPI handle_client(void *parameter) {
    CONNECTION *connection = (CONNECTION *)parameter;
    unsigned char client_init[64];
    unsigned char relay_init[64];
    HANDLE uploader = NULL;

    if (!receive_exact(connection->client, client_init, 64)) {
        goto cleanup;
    }
    if (!parse_client_init(client_init, &connection->crypto)) {
        write_text("[telegram-proxy] Rejected an invalid MTProto handshake.\r\n");
        goto cleanup;
    }
    if (!build_relay_init(&connection->crypto, relay_init)) {
        write_text("[telegram-proxy] Unable to initialize MTProto crypto.\r\n");
        goto cleanup;
    }
    if (!wss_connect(connection->crypto.dc, connection->crypto.media,
                     &connection->wss)) {
        write_text("[telegram-proxy] Telegram WebSocket is unreachable.\r\n");
        goto cleanup;
    }
    if (!wss_send(&connection->wss, relay_init, 64)) {
        int retry = connection->wss.from_pool;
        wss_close(&connection->wss);
        if (!retry ||
            !wss_connect_new(connection->crypto.dc,
                             connection->crypto.media,
                             &connection->wss) ||
            !wss_send(&connection->wss, relay_init, 64)) {
            write_text("[telegram-proxy] Unable to send the relay handshake.\r\n");
            goto cleanup;
        }
    }

    {
    char line[256];
    DWORD position = 0;
    line[0] = '\0';
    append_ascii(line, sizeof(line), &position,
                 "[telegram-proxy] Connected to Telegram DC");
    append_number(line, sizeof(line), &position,
                  (unsigned int)connection->crypto.dc);
    if (connection->crypto.media) {
        append_ascii(line, sizeof(line), &position, " media");
    }
    if (connection->wss.route == WSS_ROUTE_FRONT) {
        append_ascii(line, sizeof(line), &position, " over fronted WSS (");
        if (connection->wss.front_index >= 0 &&
            (unsigned int)connection->wss.front_index <
                sizeof(CF_FRONT_DOMAINS) / sizeof(CF_FRONT_DOMAINS[0])) {
            append_wide_ascii(line, sizeof(line), &position,
                CF_FRONT_DOMAINS[connection->wss.front_index]);
        } else {
            append_ascii(line, sizeof(line), &position, "unknown");
        }
        append_ascii(line, sizeof(line), &position, ").\r\n");
    } else if (connection->wss.route == WSS_ROUTE_REDIRECT) {
        if (connection->wss.from_pool) {
            append_ascii(line, sizeof(line), &position,
                         " over pooled direct Telegram route.\r\n");
        } else {
            append_ascii(line, sizeof(line), &position,
                         " over direct Telegram route.\r\n");
        }
    } else {
        append_ascii(line, sizeof(line), &position,
                     " over direct WSS.\r\n");
    }
    write_text(line);
    }

    uploader = CreateThread(NULL, 0, upload_thread, connection, 0, NULL);
    if (uploader == NULL) {
        goto cleanup;
    }
    download_loop(connection);
    InterlockedExchange(&connection->stop, 1);
    shutdown(connection->client, SD_BOTH);
    if (connection->wss.websocket != NULL) {
        WinHttpWebSocketClose(connection->wss.websocket,
                              WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                              NULL, 0);
    }
    WaitForSingleObject(uploader, 5000);

cleanup:
    if (uploader != NULL) {
        CloseHandle(uploader);
    }
    wss_close(&connection->wss);
    crypto_state_destroy(&connection->crypto);
    shutdown(connection->client, SD_BOTH);
    closesocket(connection->client);
    InterlockedDecrement(&active_connections);
    HeapFree(GetProcessHeap(), 0, connection);
    return 0;
}

static int run_aes_benchmark(void) {
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    const DWORD buffer_size = 16U * 1024U * 1024U;
    const unsigned int passes = 4;
    unsigned char *buffer = NULL;
    AES_CTR cipher;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t elapsed;
    uint64_t bytes_per_second;
    unsigned int pass;
    int success = 0;

    memset(&cipher, 0, sizeof(cipher));
    if (!QueryPerformanceFrequency(&frequency)) {
        goto cleanup;
    }
    buffer = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, buffer_size);
    if (buffer == NULL) {
        goto cleanup;
    }
    memset(buffer, 0x5a, buffer_size);
    if (!aes_ctr_init(&cipher, key, iv)) {
        goto cleanup;
    }
    QueryPerformanceCounter(&start);
    for (pass = 0; pass < passes; ++pass) {
        if (!aes_ctr_update(&cipher, buffer, buffer_size)) {
            goto cleanup;
        }
    }
    QueryPerformanceCounter(&end);
    elapsed = (uint64_t)(end.QuadPart - start.QuadPart);
    if (elapsed == 0) {
        goto cleanup;
    }
    bytes_per_second = (uint64_t)buffer_size * passes *
                       (uint64_t)frequency.QuadPart / elapsed;
    write_text("[aes-bench] AES-256-CTR: ");
    write_number((unsigned int)(bytes_per_second / (1024ULL * 1024ULL)));
    write_text(" MiB/s\r\n");
    success = 1;

cleanup:
    aes_ctr_destroy(&cipher);
    if (buffer != NULL) {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    if (!success) {
        write_text("[aes-bench] FAILED\r\n");
    }
    return success;
}

static int run_self_test(void) {
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const unsigned char expected[16] = {
        0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
        0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28
    };
    unsigned char block[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    unsigned char init[64];
    AES_CTR cipher;
    CRYPTO_STATE state;
    memset(&cipher, 0, sizeof(cipher));
    memset(&state, 0, sizeof(state));

    if (!aes_ctr_init(&cipher, key, iv) ||
        !aes_ctr_update(&cipher, block, 16) ||
        !bytes_equal(block, expected, 16)) {
        aes_ctr_destroy(&cipher);
        write_text("[self-test] AES-256-CTR failed.\r\n");
        return 0;
    }
    aes_ctr_destroy(&cipher);
    if (!build_obfuscated_init(PROTOCOL_PADDED, 2, 1, init) ||
        !parse_client_init(init, &state) ||
        state.protocol != PROTOCOL_PADDED || state.dc != 2 || state.media) {
        crypto_state_destroy(&state);
        write_text("[self-test] MTProto handshake failed.\r\n");
        return 0;
    }
    crypto_state_destroy(&state);
    write_text("[self-test] AES-CTR: OK\r\n");
    write_text("[self-test] MTProto handshake: OK\r\n");
    return 1;
}

static int run_wss_probe(void) {
    WSS_CONNECTION connection;
    memset(&connection, 0, sizeof(connection));
    write_text("[probe] Connecting to Telegram WSS...\r\n");
    if (!wss_connect(2, 0, &connection)) {
        write_text("[probe] Telegram WSS: FAILED\r\n");
        return 0;
    }
    write_text("[probe] Telegram WSS: OK\r\n");
    wss_close(&connection);
    return 1;
}

static int run_front_probe(void) {
    WSS_CONNECTION connection;
    memset(&connection, 0, sizeof(connection));
    write_text("[probe] Connecting to fronted Telegram WSS...\r\n");
    if (!wss_connect_front_only(2, &connection)) {
        write_text("[probe] Fronted Telegram WSS: FAILED\r\n");
        return 0;
    }
    write_text("[probe] Fronted Telegram WSS: OK\r\n");
    wss_close(&connection);
    return 1;
}

static uint64_t mtproto_message_id(void) {
    FILETIME file_time;
    ULARGE_INTEGER value;
    uint64_t unix_ticks;
    uint64_t seconds;
    uint64_t remainder;
    uint64_t fraction;
    GetSystemTimeAsFileTime(&file_time);
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    unix_ticks = value.QuadPart - 116444736000000000ULL;
    seconds = unix_ticks / 10000000ULL;
    remainder = unix_ticks % 10000000ULL;
    fraction = (remainder << 32) / 10000000ULL;
    return ((seconds << 32) | fraction) & ~3ULL;
}

static int run_client_probe(unsigned short port) {
    WSADATA socket_data;
    SOCKET socket_value = INVALID_SOCKET;
    struct sockaddr_in address;
    unsigned char init[64];
    unsigned char reverse[48];
    unsigned char key[32];
    unsigned char zeroes[64];
    unsigned char packet[44];
    unsigned char header[4];
    unsigned char *payload = NULL;
    AES_CTR encryptor;
    AES_CTR decryptor;
    DWORD timeout = 10000;
    uint32_t payload_length;
    unsigned int index;
    int success = 0;

    memset(&encryptor, 0, sizeof(encryptor));
    memset(&decryptor, 0, sizeof(decryptor));
    memset(zeroes, 0, sizeof(zeroes));

    if (WSAStartup(MAKEWORD(2, 2), &socket_data) != 0) {
        write_text("[client-probe] WSAStartup failed.\r\n");
        return 0;
    }
    socket_value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == INVALID_SOCKET) {
        goto cleanup;
    }
    setsockopt(socket_value, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout, sizeof(timeout));
    setsockopt(socket_value, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&timeout, sizeof(timeout));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(socket_value, (const struct sockaddr *)&address,
                sizeof(address)) != 0) {
        write_text("[client-probe] Local proxy is not listening.\r\n");
        goto cleanup;
    }
    if (!build_obfuscated_init(PROTOCOL_PADDED, 2, 1, init) ||
        !derive_secret_key(init + 8, key) ||
        !aes_ctr_init(&encryptor, key, init + 40) ||
        !aes_ctr_update(&encryptor, zeroes, 64)) {
        write_text("[client-probe] Unable to build the client handshake.\r\n");
        goto cleanup;
    }
    for (index = 0; index < 48; ++index) {
        reverse[index] = init[55 - index];
    }
    if (!derive_secret_key(reverse, key) ||
        !aes_ctr_init(&decryptor, key, reverse + 32)) {
        goto cleanup;
    }
    if (!send_all(socket_value, init, 64)) {
        goto cleanup;
    }

    memset(packet, 0, sizeof(packet));
    write_u32_le(packet, 40);
    write_u64_le(packet + 4, 0);
    write_u64_le(packet + 12, mtproto_message_id());
    write_u32_le(packet + 20, 20);
    write_u32_le(packet + 24, 0xBE7E8EF1U);
    if (!random_bytes(packet + 28, 16) ||
        !aes_ctr_update(&encryptor, packet, sizeof(packet)) ||
        !send_all(socket_value, packet, sizeof(packet))) {
        goto cleanup;
    }

    if (!receive_exact(socket_value, header, 4) ||
        !aes_ctr_update(&decryptor, header, 4)) {
        write_text("[client-probe] Telegram did not answer.\r\n");
        goto cleanup;
    }
    payload_length = read_u32_le(header) & 0x7FFFFFFFU;
    if (payload_length < 24 || payload_length > 1024U * 1024U) {
        write_text("[client-probe] Invalid Telegram response length.\r\n");
        goto cleanup;
    }
    payload = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, payload_length);
    if (payload == NULL ||
        !receive_exact(socket_value, payload, (int)payload_length) ||
        !aes_ctr_update(&decryptor, payload, payload_length)) {
        write_text("[client-probe] Incomplete Telegram response.\r\n");
        goto cleanup;
    }
    if (read_u32_le(payload + 20) != 0x05162463U) {
        write_text("[client-probe] Unexpected Telegram response.\r\n");
        goto cleanup;
    }
    write_text("[client-probe] Telegram resPQ: OK\r\n");
    success = 1;

cleanup:
    if (payload != NULL) {
        HeapFree(GetProcessHeap(), 0, payload);
    }
    aes_ctr_destroy(&encryptor);
    aes_ctr_destroy(&decryptor);
    if (socket_value != INVALID_SOCKET) {
        shutdown(socket_value, SD_BOTH);
        closesocket(socket_value);
    }
    WSACleanup();
    return success;
}

static void print_help(void) {
    write_text("Telegram Proxy MTProto/WSS\r\n");
    write_text("  --self-test   test AES-CTR and MTProto handshake\r\n");
    write_text("  --bench-aes   measure AES-CTR throughput\r\n");
    write_text("  --probe       test official Telegram WebSocket\r\n");
    write_text("  --probe-cf    test fronted Telegram WebSocket\r\n");
    write_text("  --bench-fronts measure all fronted routes\r\n");
    write_text("  --select-front print the fastest front index\r\n");
    write_text("  --client-probe test the full local proxy with req_pq_multi\r\n");
    write_text("  --port N      listen on 127.0.0.1:N (default 1443)\r\n");
    write_text("  --log         write a fresh diagnostic log next to the EXE\r\n");
    write_text("Secret: dd" PROXY_SECRET_HEX "\r\n");
}

void mainCRTStartup(void) {
    WSADATA socket_data;
    SOCKET listener = INVALID_SOCKET;
    struct sockaddr_in local_address;
    unsigned short port = DEFAULT_PORT;
    int argument_count = 0;
    wchar_t **arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    BOOL exclusive = TRUE;
    int index;
    int action_self_test = 0;
    int action_aes_benchmark = 0;
    int action_probe = 0;
    int action_front_probe = 0;
    int action_front_benchmark = 0;
    int action_front_selector = 0;
    int action_client_probe = 0;
    int enable_log = 0;

    if (arguments != NULL) {
        for (index = 1; index < argument_count; ++index) {
            if (wide_equals(arguments[index], L"--self-test")) {
                action_self_test = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--bench-aes")) {
                action_aes_benchmark = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--probe")) {
                action_probe = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--probe-cf")) {
                action_front_probe = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--bench-fronts")) {
                action_front_benchmark = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--select-front")) {
                action_front_selector = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--client-probe")) {
                action_client_probe = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--log")) {
                enable_log = 1;
                continue;
            }
            if (wide_equals(arguments[index], L"--help") ||
                wide_equals(arguments[index], L"-h")) {
                LocalFree(arguments);
                print_help();
                ExitProcess(0);
            }
            if (wide_equals(arguments[index], L"--port")) {
                if (index + 1 >= argument_count ||
                    !parse_port(arguments[index + 1], &port)) {
                    LocalFree(arguments);
                    write_text("[telegram-proxy] Invalid port.\r\n");
                    ExitProcess(2);
                }
                ++index;
                continue;
            }
            if (wide_equals(arguments[index], L"--front-index")) {
                LONG selected_front;
                if (index + 1 >= argument_count ||
                    !parse_front_index(arguments[index + 1],
                                       &selected_front)) {
                    LocalFree(arguments);
                    write_text("[telegram-proxy] Invalid front index.\r\n");
                    ExitProcess(2);
                }
                InterlockedExchange(&preferred_front_index, selected_front);
                ++index;
                continue;
            }
            LocalFree(arguments);
            write_text("[telegram-proxy] Unknown argument. Use --help.\r\n");
            ExitProcess(2);
        }
        LocalFree(arguments);
    }

    if (action_self_test) {
        ExitProcess(run_self_test() ? 0 : 10);
    }
    if (action_aes_benchmark) {
        ExitProcess(run_aes_benchmark() ? 0 : 15);
    }
    if (action_probe) {
        ExitProcess(run_wss_probe() ? 0 : 11);
    }
    if (action_front_probe) {
        ExitProcess(run_front_probe() ? 0 : 13);
    }
    if (action_front_benchmark) {
        ExitProcess(run_front_benchmark() ? 0 : 14);
    }
    if (action_front_selector) {
        ExitProcess(run_front_selector() ? 0 : 16);
    }
    if (action_client_probe) {
        ExitProcess(run_client_probe(port) ? 0 : 12);
    }

    if (enable_log) {
        initialize_log_file();
    }
    wss_pool_start();
    wss_pool_wait_ready(3000);

    if (WSAStartup(MAKEWORD(2, 2), &socket_data) != 0) {
        write_text("[telegram-proxy] WSAStartup failed.\r\n");
        ExitProcess(3);
    }
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        WSACleanup();
        ExitProcess(4);
    }
    setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               (const char *)&exclusive, sizeof(exclusive));

    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local_address.sin_port = htons(port);
    if (bind(listener, (const struct sockaddr *)&local_address,
             sizeof(local_address)) != 0 ||
        listen(listener, SOMAXCONN) != 0) {
        write_text("[telegram-proxy] Unable to bind 127.0.0.1:");
        write_number(port);
        write_text(".\r\n");
        closesocket(listener);
        WSACleanup();
        ExitProcess(5);
    }

    write_text("[telegram-proxy] MTProto/WSS listening on 127.0.0.1:");
    write_number(port);
    write_text(".\r\n");
    write_text("[telegram-proxy] Secret: dd" PROXY_SECRET_HEX "\r\n");
    for (;;) {
        SOCKET client = accept(listener, NULL, NULL);
        CONNECTION *connection;
        HANDLE thread;
        BOOL no_delay = TRUE;
        LONG count;
        if (client == INVALID_SOCKET) {
            continue;
        }
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&no_delay, sizeof(no_delay));
        count = InterlockedIncrement(&active_connections);
        if (count > MAX_CONNECTIONS) {
            InterlockedDecrement(&active_connections);
            closesocket(client);
            continue;
        }
        connection = (CONNECTION *)HeapAlloc(GetProcessHeap(),
                                              HEAP_ZERO_MEMORY,
                                              sizeof(CONNECTION));
        if (connection == NULL) {
            InterlockedDecrement(&active_connections);
            closesocket(client);
            continue;
        }
        connection->client = client;
        thread = CreateThread(NULL, 0, handle_client, connection, 0, NULL);
        if (thread == NULL) {
            InterlockedDecrement(&active_connections);
            closesocket(client);
            HeapFree(GetProcessHeap(), 0, connection);
            continue;
        }
        CloseHandle(thread);
    }
}
