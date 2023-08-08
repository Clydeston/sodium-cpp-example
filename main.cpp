#include <sodium.h>
int main()
{
    sodium_init();
    std::string message("test message");
    /*
      these below keys will be grabbed from wherever necessary 
      included here just for testing as this shows / server and client sides
    */
    const char hexPublicUser = (const char)"xxxx";
    const char hexPrivateUser = (const char)"xxxx";

    const char hexPrivateServer = (const char)"xxx";
    const char hexPublicServer = (const char)"xxxx";

    /*
      keys ideally stored as hex due to errors 
    */
    unsigned char binPublicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char binPrivateKey[crypto_box_SECRETKEYBYTES];
    unsigned char binServerPublic[crypto_box_PUBLICKEYBYTES];
    unsigned char binServerPrivate[crypto_box_SECRETKEYBYTES];

    /*
      converting keys from hex back to binary format
    */
    sodium_hex2bin(binPublicKey, sizeof(binPublicKey), &hexPublicUser, sizeof(hexPublicUser), NULL, NULL, NULL);
    sodium_hex2bin(binPrivateKey, sizeof(binPrivateKey), &hexPrivateUser, sizeof(hexPrivateUser), NULL, NULL, NULL);
    sodium_hex2bin(binServerPublic, sizeof(binServerPublic), &hexPublicServer, sizeof(hexPublicServer), NULL, NULL, NULL);
    sodium_hex2bin(binServerPrivate, sizeof(binServerPrivate), &hexPrivateServer, sizeof(hexPrivateServer), NULL, NULL, NULL);

    int cypherLen = crypto_box_MACBYTES + strlen(obj.c_str());

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char* cypherTxt = new unsigned char[cypherLen];
    randombytes_buf(nonce, sizeof nonce);
    if (crypto_box_easy(cypherTxt, (const unsigned char*)message.c_str(), strlen(message.c_str()), nonce,
        binServerPublic, binPrivateKey) != 0) {
        printf("errr");
    }

    printf("Encrypted %s\n", cypherTxt);

    /*
      client / 2nd receiver code
    */
    unsigned char* decryptedCypher = new unsigned char[cypherLen];
    if (crypto_box_open_easy(decryptedCypher, cypherTxt, cypherLen, nonce,
        binPublicKey, binServerPrivate) != 0) {
        printf("forged");
    }
    printf("Decrypted %s\n", cypherTxt);
return 0;
}
