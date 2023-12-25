# TLS-SSL
Chandrakanth Pokuru
chandupokuru@gmail.com

Only server auth and no Clie auth:
# Generate a private key for the CA
openssl genpkey -algorithm RSA -out ca.key

# Generate a self-signed root certificate using the private key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt



# Generate a private key for the server
openssl genpkey -algorithm RSA -out server.key

# Generate a Certificate Signing Request (CSR) for the server
openssl req -new -key server.key -out server.csr

# Sign the server CSR with the CA to create the server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# Generate a private key for the client
openssl genpkey -algorithm RSA -out client.key

# Generate a Certificate Signing Request (CSR) for the client
openssl req -new -key client.key -out client.csr

# Sign the client CSR with the CA to create the client certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256

Testing:
gcc -o server server.c -lssl -lcrypto
gcc -o client client.c -lssl -lcrypto
./server
./client
