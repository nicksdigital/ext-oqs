PHP_ARG_ENABLE(oqs, whether to enable ext-oqs support,
[ --enable-oqs  Enable ext-oqs support])

if test "$PHP_OQS" != "no"; then
  AC_DEFINE(HAVE_OQS, 1, [Whether you have ext-oqs])
  PHP_NEW_EXTENSION(oqs, oqs.c, $ext_shared)
fi
