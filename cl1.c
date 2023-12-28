#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_FILE "client.crt"
#define KEY_FILE "client.key"

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int client_fd;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
        handle_error("Error creating SSL context");

    // Load the client certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        handle_error("Error loading certificate or private key");

    // Create a new socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1)
        handle_error("Error creating socket");

    // Set up server address structure
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(8888);

    // Connect to the server
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        handle_error("Error connecting to server");

    // Create a new SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    // Perform the TLS handshake
    if (SSL_connect(ssl) <= 0)
        handle_error("Error during SSL handshake");

    // Send data to the server
    const char *message = "Hello, server!\n";
    SSL_write(ssl, message, strlen(message));

    // Receive data from the server
    char buffer[1024];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Received from server: %s", buffer);
    }

    // Close the SSL connection
    SSL_shutdown(ssl);
    close(client_fd);

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}

