#include <iostream>
#include <openssl/bn.h>
#include <openssl/dh.h>


class KeyExchangeProtocol {

public:
    KeyExchangeProtocol();
    ~KeyExchangeProtocol();
    void exchange_session_key();

private:
};
