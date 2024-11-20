mod_http_fingerprint_mod.la: mod_http_fingerprint_mod.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_http_fingerprint_mod.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_http_fingerprint_mod.la
