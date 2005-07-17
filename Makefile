# quick dirty hacks
#
DESTDIR=debian/fail2ban

all:: fail2ban.1x


fail2ban.1x: fail2ban fail2ban.h2m
	help2man --include fail2ban.h2m --section=1x --no-info --output $@ ./fail2ban

install:: all
	mkdir -p $(DESTDIR)/etc/default
	python setup.py install --root=debian/fail2ban/
	cp config/fail2ban.conf.default $(DESTDIR)/etc/fail2ban.conf
	cp config/gentoo-confd   $(DESTDIR)/etc/default/fail2ban

clean::
	rm -rf changelog.gz fail2ban.1x build* `find -iname '*.pyc' `
