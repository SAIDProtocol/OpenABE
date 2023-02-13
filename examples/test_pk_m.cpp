#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {
    constexpr int USER_COUNT = 3;

    InitializeOpenABE();

    cout << "Testing PKE context with multi-envelop" << endl;

    OpenPKEContext pke("NIST_P256", false);
//    OpenPKEContext pke;

    vector<string> users;
    for (int i = 0; i < USER_COUNT; i++) {
        string key;
        users.push_back("user" + to_string(i + 1));
        pke.keygen(users[i]);
        pke.exportPublicKey(users[i], key);
        cout << users[i] << ".PUBKEY (" << key.size() << "): " << endl << key << endl;
    }

    string pt1 = "hello world!", pt2, ct;

    pke.encryptMulti(users, pt1, ct);

    cout << "CT(" << ct.size() << "):" << endl << ct <<endl;

//    bool result = pke.decrypt("user0", ct, pt2);
//
//    assert(result && pt1 == pt2);
//
//    result = pke.decrypt("user1", ct, pt2);
//    assert(!result);
//
//    cout << "Recovered message: " << pt2 << endl;

    ShutdownOpenABE();

    return 0;
}
