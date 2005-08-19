# quick dirty hacks
#
DESTDIR=debian/fail2ban
MANPAGE=fail2ban.8
all:: $(MANPAGE)


$(MANPAGE): fail2ban fail2ban.h2m
	help2man --include fail2ban.h2m --section=1x --no-info --output $@ ./fail2ban

install:: all
	python setup.py install --root=debian/fail2ban/
	mkdir -p $(DESTDIR)/etc
	cp config/fail2ban.conf.default $(DESTDIR)/etc/fail2ban.conf

clean::
	rm -rf changelog.gz $(MANPAGE) build* `find -iname '*.pyc' `
