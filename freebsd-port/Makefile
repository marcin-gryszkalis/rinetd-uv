PORTNAME=	   rinetd-uv
PORTVERSION=	2.1.3
DISTVERSIONPREFIX= v
CATEGORIES=	 net

MAINTAINER=	 mg@fork.pl
COMMENT=		Event-driven TCP/UDP internet redirection server
WWW=			https://github.com/marcin-gryszkalis/rinetd-uv

LICENSE=		GPLv2+

USES=		   autoreconf pkgconfig

LIB_DEPENDS=	libuv.so:devel/libuv \
				libyaml.so:textproc/libyaml

USE_GITHUB=	 yes
GH_ACCOUNT=	 marcin-gryszkalis

GNU_CONFIGURE=  yes
CONFIGURE_ARGS= --sysconfdir=${PREFIX}/etc

USE_RC_SUBR=	rinetd-uv

PLIST_FILES=	sbin/rinetd-uv \
				share/man/man8/rinetd-uv.8.gz \
				"@sample etc/rinetd-uv.conf.sample" \
				etc/rinetd-uv.yaml.sample

post-install:
		@${MV} ${STAGEDIR}${PREFIX}/etc/rinetd-uv.conf \
				${STAGEDIR}${PREFIX}/etc/rinetd-uv.conf.sample
		@${MV} ${STAGEDIR}${PREFIX}/etc/rinetd-uv.yaml \
				${STAGEDIR}${PREFIX}/etc/rinetd-uv.yaml.sample

.include <bsd.port.mk>
