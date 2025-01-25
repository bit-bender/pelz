# create key and certificate for test Certificate Authority (CA)
# (need cert in both .pem and .der formats)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_ca \
            -days 30 \
            -keyout ca_priv.pem \
            -out ca_pub.pem

openssl x509 -in ca_pub.pem \
             -inform pem \
             -out ca_pub.der \
             -outform der

# create key and certificate for local pelz service node
# (need both key and cert in both .pem and .der formats)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_node \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout node_priv.pem \
            -out node_pub.pem

openssl pkey -inform pem \
             -in node_priv.pem \
             -outform der \
             -out node_priv.der

openssl x509 -inform pem \
             -in node_pub.pem \
             -outform der \
             -out node_pub.der

# create key and certificate for test ECDH proxy
# used by pelz node to access key server
# (need cert in both .pem and .der formats)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_proxy \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout proxy_priv.pem \
            -out proxy_pub.pem

openssl x509 -inform pem \
             -in proxy_pub.pem \
             -outform der \
             -out proxy_pub.der

# create key and certficate for test KMIP (simplified) key server
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_server \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout server_priv.pem \
            -out server_pub.pem

# create key and certificate for test worker enclave (pelz client)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_worker \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout worker_priv.pem \
            -out worker_pub.pem

# create key and certificate for messaging tests "requestor"
# (need certificate in both .pem and .der format)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_requestor \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout msg_test_req_priv.pem \
            -out msg_test_req_pub.pem

openssl x509 -inform pem \
             -in msg_test_req_pub.pem \
             -outform der \
             -out msg_test_req_pub.der

# create key and certificate for messaging tests "responder"
# (need both key and certificate in both .pem and .der format)
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_responder \
            -CA ca_pub.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout msg_test_resp_priv.pem \
            -out msg_test_resp_pub.pem

openssl pkey -inform pem \
             -in msg_test_resp_priv.pem \
             -outform der \
             -out msg_test_resp_priv.der

openssl x509 -inform pem \
             -in msg_test_resp_pub.pem \
             -outform der \
             -out msg_test_resp_pub.der
