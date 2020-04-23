openssl genrsa -out rsa_private_key.pem

openssl rsa -in rsa_private_key.pem -text -noout -out rsa_private_key.txt

openssl pkcs8 -in rsa_private_key.pem -topk8 -v2 aes-256-cbc -out rsa_enc_private_key.pem

openssl pkcs8 -in rsa_private_key.pem -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -out rsa_enc_private_key.pem

openssl pkcs8 -in rsa_private_key.pem -nocrypt -topk8 -out rsa_pkcs8_private_key.pem