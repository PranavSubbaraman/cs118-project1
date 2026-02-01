#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define DEFAULT_LOCAL_PORT 8443
#define DEFAULT_REMOTE_HOST "127.0.0.1"
#define DEFAULT_REMOTE_PORT 5001

int local_port = DEFAULT_LOCAL_PORT;
char remote_host[256] = DEFAULT_REMOTE_HOST;
int remote_port = DEFAULT_REMOTE_PORT;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "b:r:p:")) != -1) {
        switch (opt) {
            case 'b':
                local_port = atoi(optarg);
                break;
            case 'r':
                strncpy(remote_host, optarg, sizeof(remote_host) - 1);
                remote_host[sizeof(remote_host) - 1] = '\0';
                break;
            case 'p':
                remote_port = atoi(optarg);
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());

    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(local_port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }


    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", local_port);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        if (ssl != NULL) {
            handle_request(ssl);
        }

        // TODO: Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);

        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();

    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    printf("Received request:\n%s\n", buffer);

    char request_copy[BUFFER_SIZE];
    strncpy(request_copy, buffer, sizeof(request_copy) - 1);
    request_copy[sizeof(request_copy) - 1] = '\0';

    char *method = strtok(request_copy, " ");
    char *uri = strtok(NULL, " ");

    if (!method || !uri) {
        return;
    }

    if (uri[0] == '/') {
        uri++;
    }

    char file_name[BUFFER_SIZE];
    if (strlen(uri) == 0) {
        strcpy(file_name, "index.html");
    } else {
        url_decode(file_name, uri);
    }

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

const char *get_content_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext == NULL) {
        return "application/octet-stream";
    }
    if (strcmp(ext, ".html") == 0) {
        return "text/html; charset=UTF-8";
    } else if (strcmp(ext, ".txt") == 0) {
        return "text/plain; charset=UTF-8";
    } else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) {
        return "image/jpeg";
    } else if (strcmp(ext, ".m3u8") == 0) {
        return "application/vnd.apple.mpegurl";
    } else if (strcmp(ext, ".ts") == 0) {
        return "video/mp2t";
    }
    return "application/octet-stream";
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        // TODO: Send response via SSL
        SSL_write(ssl, response, strlen(response));
        return;
    }

    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n\r\n",
             get_content_type(path));

    // TODO: Send response header and file content via SSL
    SSL_write(ssl, response, strlen(response));

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1></body></html>";
        SSL_write(ssl, response, strlen(response));
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, remote_host, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(remote_port);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1></body></html>";
        SSL_write(ssl, response, strlen(response));
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        SSL_write(ssl, buffer, bytes_read);
    }

    close(remote_socket);
}
