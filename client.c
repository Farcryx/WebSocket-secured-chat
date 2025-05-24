#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <math.h>
#include <openssl/buffer.h>

int Number();
int OptimusPrimeNumber();
int aes_gcm_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *nonce, int nonce_len,
    unsigned char *plaintext);
void bin_to_hex(const unsigned char *bin, size_t len, char *hex_out);
int hexstr_to_bytes(const char *hexstr, unsigned char *outbuf);
unsigned long long mod_exp(unsigned long long base, unsigned long long exp, unsigned long long mod);
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, int key_len,
                    const unsigned char *nonce, int nonce_len,
                    unsigned char *ciphertext,
                    unsigned char *tag, int tag_len);

#pragma comment(lib, "ws2_32.lib")

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Srand set
    srand(time(NULL));

#define MAX_LEN 256
#define AES_KEY_LEN 16

    char *sync;
    char message[1024];

    char UserName[1024];
    char Password[1024];

    struct sockaddr_in servaddr = {0};
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(3443);
    servaddr.sin_addr.s_addr = inet_addr("192.168.1.104");

    int option = 0;
    int connected = 0;
    char clear[10];

    char nonce[32];
    unsigned char Key[16];
    int nonce_len;

    do
    {
        printf("Choose option\r\n 1 - Connect to chat\r\n 2 - register\r\n 3 - login\r\n 4 - Exit program\r\n Before you send message you must first connect\r\n");
        printf("\r\n> ");
        scanf("%d", &option);

        fgets(clear, sizeof(clear), stdin);

        switch (option)
        {
        case 2:
            char input_buffer_one[1024] = {0};
            int input_pos_one = 0;
            char last_recv[1024] = {0};
            unsigned char ciphertext2[32];
            unsigned char tag4[16];
            char message2[128];

            if (!connected)
            {
                printf("First connect to the server (option 1).\n");
                break;
            }

            do
            {

                printf("Enter Username\r\n");
                printf(">>> ");
                fgets(UserName, sizeof(UserName), stdin);
                UserName[strcspn(UserName, "\n")] = 0;

                printf("Enter Password\r\n");
                printf(">>> ");
                fgets(Password, sizeof(Password), stdin);
                Password[strcspn(Password, "\n")] = 0;

                sprintf(message, "%s:%s", UserName, Password);

                aes_gcm_encrypt((unsigned char *)message, strlen(message),
                                Key, AES_KEY_LEN,
                                nonce, nonce_len,
                                ciphertext2, tag4, 16);

                char cipher_hex[65];
                char tag4_hex[33];

                bin_to_hex(ciphertext2, 16, cipher_hex);
                bin_to_hex(tag4, 16, tag4_hex);

                sprintf(message2, "${SIGNUP_TAG}:%s:%s:%s", nonce, cipher_hex, tag4_hex);

                sendto(sock, message2, strlen(message2), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

                while (1)
                {
                    fd_set readfds;
                    struct timeval tv = {0, 0};
                    FD_ZERO(&readfds);
                    FD_SET(sock, &readfds);

                    int result = select(0, &readfds, NULL, NULL, &tv);
                    if (result > 0 && FD_ISSET(sock, &readfds))
                    {
                        char recvbuf[1024];
                        memset(recvbuf, 0, sizeof(recvbuf));
                        int bytes = recvfrom(sock, recvbuf, sizeof(recvbuf) - 1, 0,
                                             (struct sockaddr *)&from, &fromlen);
                        if (bytes > 0)
                        {
                            recvbuf[bytes] = '\0';
                            printf("\n  %s\n\r %s", recvbuf, input_buffer_one); //
                            fflush(stdout);

                            strcpy(last_recv, recvbuf);
                            break;
                        }
                    }
                }

            } while (strcmp(last_recv, "<From Server> SIGNUP_OK") == 0);

            break;

        case 3:

            char input_buffer_two[1024] = {0};
            int input_pos_two = 0;
            char last_recv2[1024] = {0};

            char cipher_hex2[65];
            char tag4_hex2[33];
            unsigned char ciphertext4[32];
            unsigned char tag5[16];
            char message3[128];

            if (!connected)
            {
                printf("First connect to the server (option 1).\n\r");
                break;
            }
            do
            {
                printf("Enter Username\r\n");
                printf(">>> ");
                fgets(UserName, sizeof(UserName), stdin);
                UserName[strcspn(UserName, "\n")] = 0;

                printf("Enter Password\r\n");
                printf(">>> ");
                fgets(Password, sizeof(Password), stdin);
                Password[strcspn(Password, "\n")] = 0;

                sprintf(message, "%s:%s", UserName, Password);

                aes_gcm_encrypt((unsigned char *)message, strlen(message),
                                Key, AES_KEY_LEN,
                                nonce, nonce_len,
                                ciphertext2, tag4, 16);

                bin_to_hex(ciphertext4, 16, cipher_hex2);
                bin_to_hex(tag5, 16, tag4_hex2);

                sprintf(message2, "${SIGNIN_TAG}:%s:%s:%s", nonce, cipher_hex2, tag4_hex2);

                sendto(sock, message2, strlen(message2), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

                while (1)
                {
                    fd_set readfds;
                    struct timeval tv = {0, 0};
                    FD_ZERO(&readfds);
                    FD_SET(sock, &readfds);
                    int result = select(0, &readfds, NULL, NULL, &tv);
                    if (result > 0 && FD_ISSET(sock, &readfds))
                    {
                        char recvbuf[1024];
                        memset(recvbuf, 0, sizeof(recvbuf));
                        int bytes = recvfrom(sock, recvbuf, sizeof(recvbuf) - 1, 0,
                                             (struct sockaddr *)&from, &fromlen);
                        if (bytes > 0)
                        {
                            recvbuf[bytes] = '\0';
                            printf("\n %s\n> %s", recvbuf, input_buffer_two); //
                            fflush(stdout);

                            strcpy(last_recv2, recvbuf);
                            break;
                        }
                    }
                }

            } while (strcmp(last_recv2, "<From Server> SIGNIN_OK") == 0);

            do
            {
                fd_set readfds;
                struct timeval tv = {0, 0};
                FD_ZERO(&readfds);
                FD_SET(sock, &readfds);

                int result = select(0, &readfds, NULL, NULL, &tv);
                if (result > 0 && FD_ISSET(sock, &readfds))
                {
                    char recvbuf[1024];
                    memset(recvbuf, 0, sizeof(recvbuf));
                    int bytes = recvfrom(sock, recvbuf, sizeof(recvbuf) - 1, 0,
                                         (struct sockaddr *)&from, &fromlen);
                    if (bytes > 0)
                    {
                        recvbuf[bytes] = '\0';
                        printf("\n  %s\n> %s", recvbuf, input_buffer_two);
                        fflush(stdout);
                    }
                }

                if (_kbhit())
                {
                    char ch = _getch();

                    if (ch == '\r')
                    {
                        input_buffer_two[input_pos_two] = '\0';
                        printf("\n");

                        if (strcmp(input_buffer_two, "EXIT CHAT") == 0)
                            break;

                        sendto(sock, input_buffer_two, strlen(input_buffer_two), 0,
                               (struct sockaddr *)&servaddr, sizeof(servaddr));
                        input_pos_two = 0;
                        input_buffer_two[0] = '\0';
                        printf(">>> ");
                    }
                    else if (ch == '\b')
                    {
                        if (input_pos_two > 0)
                        {
                            input_pos_two--;
                            input_buffer_two[input_pos_two] = '\0';
                            printf("\b \b");
                            fflush(stdout);
                        }
                    }
                    else
                    {
                        if (input_pos_two < sizeof(input_buffer_two) - 1)
                        {
                            input_buffer_two[input_pos_two++] = ch;
                            input_buffer_two[input_pos_two] = '\0';
                            printf("%c", ch);
                            fflush(stdout);
                        }
                    }
                }
            } while (1 == 1);

            break;

        case 1:

            int gekon;
            char LittleOne;

            int a;
            int g;
            int A;
            int p;
            char hex_strA[16];
            char hex_strg[16];
            char hex_strp[16];
            char packet[128];
            char packet2[128];
            char recvbuf[1024];
            char input[1024];
            int wynik;
            int wynik2;

            sync = "${CONNECT_TAG}";
            a = Number();
            g = Number();
            p = OptimusPrimeNumber();

            A = mod_exp(g, a, p);
            sprintf(hex_strA, "%X", A);
            sprintf(hex_strg, "%X", g);
            sprintf(hex_strp, "%X", p);

            snprintf(packet, sizeof(packet), "%s:%s:%s:%s", sync, hex_strA, hex_strg, hex_strp);

            sendto(sock, packet, strlen(packet), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
            do
            {
                fd_set readfds;
                struct timeval tv = {0, 0};
                FD_ZERO(&readfds);

                FD_SET(sock, &readfds);
                int result = select(0, &readfds, NULL, NULL, &tv);
                if (result > 0 && FD_ISSET(sock, &readfds))
                {

                    memset(recvbuf, 0, sizeof(recvbuf));
                    int bytes = recvfrom(sock, recvbuf, sizeof(recvbuf) - 1, 0,
                                         (struct sockaddr *)&from, &fromlen);
                    if (bytes > 0)
                    {
                        recvbuf[bytes] = '\0';
                        printf("\n %s\n> %s", recvbuf, input_buffer_two); //
                        fflush(stdout);

                        strcpy(input, recvbuf);

                        int gekon = 1;
                        break;
                    }
                }
            } while (gekon != 1);

            char B[10], encrypted_message[512], tag2[64];

            char *token = strtok(input, ":");

            token = strtok(NULL, ":");
            if (token)
            {
                strncpy(B, token, sizeof(B));
                B[sizeof(B) - 1] = '\0';
            }
            token = strtok(NULL, ":");
            if (token)
            {
                strncpy(nonce, token, sizeof(nonce));
                nonce[sizeof(nonce) - 1] = '\0';
            }
            token = strtok(NULL, ":");
            if (token)
            {
                strncpy(encrypted_message, token, sizeof(encrypted_message));
                encrypted_message[sizeof(encrypted_message) - 1] = '\0';
            }
            token = strtok(NULL, ":");
            if (token)
            {
                strncpy(tag2, token, sizeof(tag2));
                tag2[sizeof(tag2) - 1] = '\0';
            }
            printf("nonce: %s\n", nonce);
            unsigned char nonce_bin[12];
            unsigned char ciphertext[256];
            unsigned char tag[16];
            hexstr_to_bytes(nonce, nonce_bin);
            hexstr_to_bytes(encrypted_message, ciphertext);
            hexstr_to_bytes(tag2, tag);

            int ct_len = hexstr_to_bytes(encrypted_message, ciphertext);
            int tag_len = hexstr_to_bytes(tag2, tag);
            nonce_len = hexstr_to_bytes(nonce, nonce_bin);

            int value = (int)strtol(B, NULL, 16);
            unsigned long long shared = mod_exp(value, a, p);

            char shared_str[64];
            sprintf(shared_str, "%llu", shared);

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char *)shared_str, strlen(shared_str), hash);
            memcpy(Key, hash, 16);

            unsigned char decrypted[256];
            int decrypted_len = aes_gcm_decrypt(ciphertext, ct_len, tag, Key, nonce_bin, nonce_len, decrypted);

            unsigned char ciphertext3[32];
            unsigned char tag3[16];

            aes_gcm_encrypt(Key, sizeof(Key),     // plaintext = Key
                            Key, sizeof(Key),     // key = Key
                            nonce_bin, nonce_len, // nonce = odebrane nonce z serwera
                            ciphertext3, tag3, sizeof(tag3));

            char hex_key[65];
            bin_to_hex(ciphertext3, 16, hex_key);
            printf("HEX Key: %s\n", hex_key);

            char hex_tag[33];
            bin_to_hex(tag3, 16, hex_tag);
            printf("HEX Key: %s\n", hex_tag);

            char *AUTH_TAG = "${AUTH_TAG}";

            snprintf(packet2, sizeof(packet2), "%s:%s:%s:%s", AUTH_TAG, nonce, hex_key, hex_tag);
            sendto(sock, packet2, strlen(packet2), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

            connected = 1;
            printf("Connected to server.\n\r");
            break;

        default:

            printf("wrong option\r\n");

            break;
        }

    } while (option != 4);

    closesocket(sock);
    WSACleanup();

    return 0;
}

int Number()
{

    int min = 1;
    int max = 200;

    int rd_num = rand() % (max - min + 1) + min;

    return rd_num;
}

int OptimusPrimeNumber()
{
    int min = 1;
    int max = 200;
    bool yep = false;
    int rd_num2;
    int x;

    do
    {
        rd_num2 = rand() % (max - min + 1) + min;
        x = 0;

        for (int i = 2; i <= rd_num2 / 2; ++i)
        {
            if (rd_num2 % i == 0)
            {
                x = 1;
                break;
            }
        }

        if (x != 1)
        {
            yep = true;
        }

    } while (yep == false);

    return rd_num2;
}

int aes_gcm_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *nonce, int nonce_len,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    if (!ctx)
        return -1;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    return ret > 0 ? plaintext_len + len : -1;
}

int hexstr_to_bytes(const char *hexstr, unsigned char *outbuf)
{
    long len = 0;
    unsigned char *buf = OPENSSL_hexstr2buf(hexstr, &len);

    memcpy(outbuf, buf, len);
    OPENSSL_free(buf);

    return len;
}

unsigned long long mod_exp(unsigned long long base, unsigned long long exp, unsigned long long mod)
{
    unsigned long long result = 1;
    base = base % mod;

    while (exp > 0)
    {
        if (exp % 2 == 1)
            result = (result * base) % mod;

        exp = exp >> 1;
        base = (base * base) % mod;
    }

    return result;
}

void bin_to_hex(const unsigned char *bin, size_t len, char *hex_out)
{
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i)
    {
        hex_out[i * 2] = hex_chars[(bin[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex_chars[bin[i] & 0xF];
    }
    hex_out[len * 2] = '\0'; // zakończenie stringa
}

int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, int key_len,
                    const unsigned char *nonce, int nonce_len,
                    unsigned char *ciphertext,
                    unsigned char *tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len, ret;

    if (!ctx)
        return -1;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}