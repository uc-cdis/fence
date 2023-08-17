#/bin/bash

# MEANT FOR LOCAL DEV ONLY


# Run:
# 1. this script
# 2. docker-compose up -d
# 3. ./init_client_in_db.sh


mkdir keys/v1

cd keys/v1

# Generate the private key.
openssl genpkey -algorithm RSA -out jwt_private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate the public key.
openssl rsa -pubout -in jwt_private_key.pem -out jwt_public_key.pem
