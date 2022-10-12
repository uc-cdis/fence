psql -h localhost -U postgres -c 'SELECT version();'
psql -h localhost -U postgres -c "create database fence_test_tmp"
pip list

sudo rm -f /etc/boto.cfg
mkdir -p tests/resources/keys 

cd tests/resources/keys 
openssl genrsa -out test_private_key.pem 2048
openssl rsa -in test_private_key.pem -pubout -out test_public_key.pem

openssl genrsa -out test_private_key_2.pem 2048
openssl rsa -in test_private_key_2.pem -pubout -out test_public_key_2.pem

cd -
