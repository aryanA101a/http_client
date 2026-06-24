PROG=	http_client
MAN=

.OBJDIR: ${.CURDIR}/build

BEARSSL_DIR=	${.CURDIR}/BearSSL
BEARSSL_LIB=	${BEARSSL_DIR}/build/libbearssl.a

.PATH: ${BEARSSL_DIR}/tools

SRCS=	http_client.c \
	certs.c \
	files.c \
	names.c \
	vector.c \
	xmem.c

CFLAGS+=	-I${BEARSSL_DIR}/inc -I${BEARSSL_DIR}/tools
DPADD+=		${BEARSSL_LIB}
LDADD+=		${BEARSSL_LIB}

.PHONY: bearssl
bearssl:
	${MAKE} -C ${BEARSSL_DIR} lib

${BEARSSL_LIB}: bearssl

.include <bsd.prog.mk>
