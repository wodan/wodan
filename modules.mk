mod_wodan2.la: mod_wodan2.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_wodan2.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_wodan2.la
