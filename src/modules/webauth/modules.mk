mod_webauth.la: mod_webauth.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_webauth.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_webauth.la
