#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

SSL_CTX *create_client_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, "/Users/cpokur625/Documents/ckp/learning/openssl/server/server.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    SSL_CTX *ctx;

    ctx = create_client_context();
    configure_client_context(ctx);

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char *message = "Hello from the client!";
        SSL_write(ssl, message, strlen(message));

        char buffer[1024] = {0};
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Received from server: %s\n", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    SSL_CTX_free(ctx);

    return 0;
}

