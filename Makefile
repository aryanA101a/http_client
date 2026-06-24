PROG=	http_client
MAN=

.OBJDIR: ${.CURDIR}/build

BEARSSL_DIR=	${.CURDIR}/BearSSL
BEARSSL_LIB=	${BEARSSL_DIR}/build/libbearssl.a
BEARSSL_TA=	${BEARSSL_DIR}/build/brssl

FREEBSD_SRC?=	${.CURDIR}/../freebsd/vendor-exp/freebsd-src
CAROOT_DIR=	${FREEBSD_SRC}/secure/caroot/trusted

.if !exists(${CAROOT_DIR})
.error "FreeBSD trusted root directory not found: ${CAROOT_DIR}"
.endif

TRUST_ANCHORS_INC=	trust_anchors.inc

SRCS=	http_client.c

CFLAGS+=	-I${BEARSSL_DIR}/inc -I${.OBJDIR}
DPADD+=		${BEARSSL_LIB}
LDADD+=		${BEARSSL_LIB}
CLEANFILES+=	${TRUST_ANCHORS_INC}

http_client.o: ${TRUST_ANCHORS_INC}

${TRUST_ANCHORS_INC}: ${BEARSSL_TA}
	${BEARSSL_TA} ta -q ${CAROOT_DIR}/*.pem > ${.TARGET}

.PHONY: bearssl
bearssl:
	${MAKE} -C ${BEARSSL_DIR} lib tools

${BEARSSL_LIB}: bearssl
${BEARSSL_TA}: bearssl

.include <bsd.prog.mk>
