mod_http_fingerprint.la: mod_http_fingerprint.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_http_fingerprint.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_http_fingerprint.la
