// Template was: http://fm4dd.com/openssl/pkcs12test.htm

// Steps for selfsigned cert:
//    openssl genrsa -out key.pem 2048
//    openssl req -new -sha256 -key key.pem -out csr.csr
//    openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

int main() {
    X509           *cert;
    EVP_PKEY       *cert_privkey;
    BIO            *bio_key, *bio_cert;
    PKCS12         *pkcs12bundle;

    char pem_key_buffer[] = "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEA4DQvkW3UgVSItA2dEYbf+NDuDGtEzQ6NUTOWgpUk6wG46EaQ\n"
    "Zao7i/3hEzndr/QHMzlcfdMYNJdwO982Ai5vOe5C7skuTE9cLsfTwDhfzn5wVU2R\n"
    "Se0QfvzfQtlDmcIsGb1aT1ypGcIoSTMAdTe3/AmKlaMn3L/vh7dUDTBAeJrT/jQC\n"
    "mZp3MY05HWE2qGv+qNZSaubO0MeX1m9Mxnv82mZbyXZy3EKtuu4TCFPZsbT/5NGc\n"
    "qRR/IS+DgTiWqFdWiJJThxkBitl32dobD3e0A6aQG2MaGAXfoW1E1sjOExsBHn69\n"
    "AzurrGiBfT2hkgbtsRNHZv/yc96RKy+uM01doQIDAQABAoIBAFknx2awYxnO0NGw\n"
    "vC31EWlzQ8ZCfciBKecJeaeRwW2GcM5FCTS0XhuMKI2prCNFCfvvqn0KjYyUT/gv\n"
    "Cd4SMv65ZXppG/USddjQc77za/3EP81cHBNmpvGoguulVAF3umu95YS7ly78C2MY\n"
    "We1C6/HYpXhdugNJe+nfGBhqgKi0Qlo9v8jQrzb0qVfbmEVGuXOS8QFwuCtrUnuX\n"
    "uiN/O4nwx+pauYFMIcNrIhTowYp6p5fHGJlzxsJC8NZukxZjeyJ2OD2eYiptwVOO\n"
    "9MVSiLJRAOVZBr1K8/e0RjILl7jGOtThD8XuEgx15s9fmrX7quNe4Px0QtKgeTzZ\n"
    "Egbk6cECgYEA85SErIfHE1tYLzaDlztB5WnNZsiQ4vX3hgAv8zTMiPNIEoFeme7t\n"
    "cV975J7a+agKp2qDmeqYqDkClquVpiziAl0BA+Hi2/pYUIi6Gm0+l49959EwvFA0\n"
    "qRB8IcCvEekaaztZZzjFodpgWlWVXW3xpcMmD3BqgoGM1VFGY2ma7GkCgYEA66K/\n"
    "EBCLTEPLhBOXRznbwI9u4OxV9uUBG4sAGf3iHDNNnYr7czzxZyatY9vuv33SXT9e\n"
    "gADBrgDOEn4eTXzgiHWKvgyBUzlf04DIsQPA9GgKQLYnSPZVKhWZwvHG2ZSm+SEK\n"
    "03K4/izCMKu5ktuJJ9ZBVxbhM0Asn5jH9CiCoHkCgYBV+1EyDePKA26Hi/i7g6Fp\n"
    "OAXXiGkMlMLBPIOwmCyzEx2X2q7oK50JbikvtJubkSPhoQm/ZT5p82XkhcEXnbRS\n"
    "HT5kfnI0MJTIKNt4xKNZoL9S+1b2wmE0ZKtMxtWFvwEiZRrUAwhQb+OfP6KwDkVE\n"
    "vDRNMuOGGfD6w+vS385eMQKBgDvrGXyjSFivUJwYQzqYatnvXzmQv1dV6k8vrGnv\n"
    "lkSngxARnFk0YQpi2mpvLanB+/E8QPJ5vsZZbA1lxpzbqVjp0sr68RPRnh1xPRdO\n"
    "Jg3AOwMzjo/OG9/kuEHLK05+r2rgTRlxrbrsdMDdmgXPD3Ry1hCoP8HBitdWiVn7\n"
    "xyO5AoGAJMwJWJ2RdV0F9kgtmpnf/J50ji4Odyj7AcQ/nI6oytR/WIJt31wBx3Gc\n"
    "36kPuhEoB0ENC3PP7l6zkthKEC+zDbjGW9XMr6BuRcnsh2QPc+JbnXXj10zv4q7u\n"
    "PV1bfiEPiuHN6MTAFTBpm3etZMbbEWX3iFuSpfME0K+/Y9Fjq9A=\n"
    "-----END RSA PRIVATE KEY-----\n";

    char pem_cert_buffer[] = "-----BEGIN CERTIFICATE-----\n"
    "MIID7jCCAtYCCQDn4LnlmYY2vjANBgkqhkiG9w0BAQsFADCBtzELMAkGA1UEBhMC\n"
    "QVQxFjAUBgNVBAgMDVVwcGVyIEF1c3RyaWExDTALBgNVBAcMBExpbnoxITAfBgNV\n"
    "BAoMGFNvcGhvcyBVbml0IHRlc3QgY29tcGFueTEUMBIGA1UECwwLVGVzdGluZyA7\n"
    "LSkxIDAeBgNVBAMMF2NvbS5zb3Bob3MudW5pdHRlc3Quc21jMSYwJAYJKoZIhvcN\n"
    "AQkBFhdkby1ub3QtcmVwbHlAc29waG9zLmNvbTAgFw0xODEwMTEwODU1MzVaGA8y\n"
    "MTU1MDkwMzA4NTUzNVowgbcxCzAJBgNVBAYTAkFUMRYwFAYDVQQIDA1VcHBlciBB\n"
    "dXN0cmlhMQ0wCwYDVQQHDARMaW56MSEwHwYDVQQKDBhTb3Bob3MgVW5pdCB0ZXN0\n"
    "IGNvbXBhbnkxFDASBgNVBAsMC1Rlc3RpbmcgOy0pMSAwHgYDVQQDDBdjb20uc29w\n"
    "aG9zLnVuaXR0ZXN0LnNtYzEmMCQGCSqGSIb3DQEJARYXZG8tbm90LXJlcGx5QHNv\n"
    "cGhvcy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgNC+RbdSB\n"
    "VIi0DZ0Rht/40O4Ma0TNDo1RM5aClSTrAbjoRpBlqjuL/eETOd2v9AczOVx90xg0\n"
    "l3A73zYCLm857kLuyS5MT1wux9PAOF/OfnBVTZFJ7RB+/N9C2UOZwiwZvVpPXKkZ\n"
    "wihJMwB1N7f8CYqVoyfcv++Ht1QNMEB4mtP+NAKZmncxjTkdYTaoa/6o1lJq5s7Q\n"
    "x5fWb0zGe/zaZlvJdnLcQq267hMIU9mxtP/k0ZypFH8hL4OBOJaoV1aIklOHGQGK\n"
    "2XfZ2hsPd7QDppAbYxoYBd+hbUTWyM4TGwEefr0DO6usaIF9PaGSBu2xE0dm//Jz\n"
    "3pErL64zTV2hAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHIlmZmLINeM2PrH4eiA\n"
    "CMxDz66L01AXu7I7LNMEzspwWL3esZ+/xwK2vXxt+JXi7nkLA9w5h1vNt9Xapm7q\n"
    "b/nNldBXuLL7k3kbLJSNZ9HDkv7bolWl3d50f9si/YwhK4dQvuq1AqGVSBT/oANn\n"
    "GExCw8/cNLQoftfaJ2vjJgTWz+YTAkRvjXE/fbg0Iy9Gg5VD0lanN66kr/OTrL1F\n"
    "4uVAQh12s/JfYxxCzqm6G9btmqcOLziQkT7EYQYTqsIlcx9ce8i8erRJCa70kdYO\n"
    "mzlkN8d1dcY2NQ/oBhNcmGGbXZwVU5WyTouXBtlvjyKtgPR44f/tkxkCoKtk1krd\n"
    "wak=\n"
    "-----END CERTIFICATE-----\n";

    /* ------------------------------------------------------------ *
     * 1.) These function calls are essential to make PEM_read and  *
     *     other openssl functions work.                            *
     * ------------------------------------------------------------ */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* ------------------------------------------------------------ *
     * 2.) Init buffers with pem data                               *
     * ------------------------------------------------------------ */
    bio_key = BIO_new_mem_buf(pem_key_buffer, strlen(pem_key_buffer));
    bio_cert = BIO_new_mem_buf(pem_cert_buffer, strlen(pem_cert_buffer));

    /*--------------------------------------------------------------*
     * 3.) we load the certificates private key                     *
     *    ( for this test, it has no password )                     *
     *--------------------------------------------------------------*/
    if ((cert_privkey = EVP_PKEY_new()) == NULL) {
        printf("Error creating EVP_PKEY structure.\n");
    }

    if (! (cert_privkey = PEM_read_bio_PrivateKey(bio_key, NULL, 0, NULL))) {
        printf("Error loading certificate private key content.\n");
    }

    /*--------------------------------------------------------------*
     * 4.) we load the corresponding certificate                    *
     *--------------------------------------------------------------*/
    if (! (cert = PEM_read_bio_X509(bio_cert, NULL, 0, NULL))) {
        printf("Error loading cert into memory.\n");
    }

    /*--------------------------------------------------------------*
     * 6.) we create the PKCS12 structure and fill it with our data *
     *--------------------------------------------------------------*/
    if ((pkcs12bundle = PKCS12_new()) == NULL)
        printf("Error creating PKCS12 structure.\n");

    /* values of zero use the openssl default values */
    pkcs12bundle = PKCS12_create(
                                 "test",      // certbundle access password
                                 "privatekey",// friendly certname
                                 cert_privkey,// the certificate private key
                                 cert,        // the main certificate
                                 NULL,        // stack of CA cert chain
                                 0,           // int nid_key (default 3DES)
                                 0,           // int nid_cert (40bitRC2)
                                 0,           // int iter (default 2048)
                                 0,           // int mac_iter (default 1)
                                 0            // int keytype (default no flag)
                                 );

    if ( pkcs12bundle == NULL) {
        ERR_print_errors_fp(stderr);
        printf("Error generating a valid PKCS12 certificate.\n");
    }


    // CertificateHelper store cert cert_privkey


    /*--------------------------------------------------------------*
     * 8.) we are done, let's clean up                              *
     *--------------------------------------------------------------*/
    X509_free(cert);
    PKCS12_free(pkcs12bundle);
}
