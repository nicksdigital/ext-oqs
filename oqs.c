#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"  // Include this header for php_info_print_table_* functions
#include <oqs/oqs.h>

static int le_oqs;

ZEND_BEGIN_ARG_INFO_EX(arginfo_oqs_kem_new, 0, 0, 1)
    ZEND_ARG_INFO(0, method_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oqs_kem_free, 0, 0, 1)
    ZEND_ARG_INFO(0, kem_res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oqs_kem_keypair, 0, 0, 1)
    ZEND_ARG_INFO(0, kem_res)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oqs_kem_encaps, 0, 0, 2)
    ZEND_ARG_INFO(0, kem_res)
    ZEND_ARG_INFO(0, public_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_oqs_kem_decaps, 0, 0, 3)
    ZEND_ARG_INFO(0, kem_res)
    ZEND_ARG_INFO(0, ciphertext)
    ZEND_ARG_INFO(0, secret_key)
ZEND_END_ARG_INFO()

PHP_FUNCTION(oqs_kem_new) {
    char *method_name;
    size_t method_name_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &method_name, &method_name_len) == FAILURE) {
        RETURN_FALSE;
    }

    OQS_KEM *kem = OQS_KEM_new(method_name);
    if (kem == NULL) {
        RETURN_FALSE;
    }

    RETURN_RES(zend_register_resource(kem, le_oqs));
}

PHP_FUNCTION(oqs_kem_free) {
    zval *kem_res;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &kem_res) == FAILURE) {
        RETURN_FALSE;
    }

    OQS_KEM *kem = (OQS_KEM *)zend_fetch_resource(Z_RES_P(kem_res), "OQS KEM", le_oqs);
    if (!kem) {
        RETURN_FALSE;
    }

    OQS_KEM_free(kem);
    RETURN_TRUE;
}

PHP_FUNCTION(oqs_kem_keypair) {
    zval *kem_res;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "r", &kem_res) == FAILURE) {
        RETURN_FALSE;
    }

    OQS_KEM *kem = (OQS_KEM *)zend_fetch_resource(Z_RES_P(kem_res), "OQS KEM", le_oqs);
    if (!kem) {
        RETURN_FALSE;
    }

    unsigned char *public_key = emalloc(kem->length_public_key);
    unsigned char *secret_key = emalloc(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        efree(public_key);
        efree(secret_key);
        RETURN_FALSE;
    }

    array_init(return_value);
    add_next_index_stringl(return_value, (char *)public_key, kem->length_public_key);
    add_next_index_stringl(return_value, (char *)secret_key, kem->length_secret_key);

    efree(public_key);
    efree(secret_key);
}

PHP_FUNCTION(oqs_kem_encaps) {
    zval *kem_res;
    char *public_key;
    size_t public_key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &kem_res, &public_key, &public_key_len) == FAILURE) {
        RETURN_FALSE;
    }

    OQS_KEM *kem = (OQS_KEM *)zend_fetch_resource(Z_RES_P(kem_res), "OQS KEM", le_oqs);
    if (!kem) {
        RETURN_FALSE;
    }

    unsigned char *ciphertext = emalloc(kem->length_ciphertext);
    unsigned char *shared_secret = emalloc(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, (const uint8_t *)public_key) != OQS_SUCCESS) {
        efree(ciphertext);
        efree(shared_secret);
        RETURN_FALSE;
    }

    array_init(return_value);
    add_next_index_stringl(return_value, (char *)ciphertext, kem->length_ciphertext);
    add_next_index_stringl(return_value, (char *)shared_secret, kem->length_shared_secret);

    efree(ciphertext);
    efree(shared_secret);
}

PHP_FUNCTION(oqs_kem_decaps) {
    zval *kem_res;
    char *ciphertext;
    size_t ciphertext_len;
    char *secret_key;
    size_t secret_key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "rss", &kem_res, &ciphertext, &ciphertext_len, &secret_key, &secret_key_len) == FAILURE) {
        RETURN_FALSE;
    }

    OQS_KEM *kem = (OQS_KEM *)zend_fetch_resource(Z_RES_P(kem_res), "OQS KEM", le_oqs);
    if (!kem) {
        RETURN_FALSE;
    }

    unsigned char *shared_secret = emalloc(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret, (const uint8_t *)ciphertext, (const uint8_t *)secret_key) != OQS_SUCCESS) {
        efree(shared_secret);
        RETURN_FALSE;
    }

    RETVAL_STRINGL((char *)shared_secret, kem->length_shared_secret);

    efree(shared_secret);
}

const zend_function_entry oqs_functions[] = {
    PHP_FE(oqs_kem_new, arginfo_oqs_kem_new)
    PHP_FE(oqs_kem_free, arginfo_oqs_kem_free)
    PHP_FE(oqs_kem_keypair, arginfo_oqs_kem_keypair)
    PHP_FE(oqs_kem_encaps, arginfo_oqs_kem_encaps)
    PHP_FE(oqs_kem_decaps, arginfo_oqs_kem_decaps)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(oqs) {
    le_oqs = zend_register_list_destructors_ex(NULL, NULL, "OQS KEM", module_number);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(oqs) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(oqs) {
    php_info_print_table_start();
    php_info_print_table_header(2, "oqs support", "enabled");
    php_info_print_table_end();
}

zend_module_entry oqs_module_entry = {
    STANDARD_MODULE_HEADER,
    "oqs",
    oqs_functions,
    PHP_MINIT(oqs),
    PHP_MSHUTDOWN(oqs),
    NULL,
    NULL,
    PHP_MINFO(oqs),
    NO_VERSION_YET,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OQS
ZEND_GET_MODULE(oqs)
#endif
