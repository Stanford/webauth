mod_webauth.la: mod_webauth.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_webauth.lo\
          ../../libwebauth/libwebauth.a
DISTCLEAN_TARGETS = modules.mk 
shared =  mod_webauth.la

#	$(SH_LINK) -L../../libwebauth -lwebauth -rpath $(libexecdir) -module -avoid-version  mod_webauth.lo