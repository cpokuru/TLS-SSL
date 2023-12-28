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

#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, client_fd;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx)
        handle_error("Error creating SSL context");

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        handle_error("Error loading certificate or private key");

    // Create a new socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
        handle_error("Error creating socket");

    // Set up server address structure
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8888);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        handle_error("Error binding socket");

    // Listen for incoming connections
    if (listen(server_fd, 10) == -1)
        handle_error("Error listening on socket");

    printf("Server is listening on port 8888...\n");

    // Accept incoming connections
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            handle_error("Error accepting connection");

        // Create a new SSL connection
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        // Perform the TLS handshake
        if (SSL_accept(ssl) <= 0)
            handle_error("Error during SSL handshake");

        // Send a welcome message
        const char *welcome_msg = "Welcome to the server!\n";
        SSL_write(ssl, welcome_msg, strlen(welcome_msg));

        // Receive data from the client
        char buffer[1024];
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Received from client: %s", buffer);
        }

        // Close the SSL connection
        SSL_shutdown(ssl);
        close(client_fd);
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}

