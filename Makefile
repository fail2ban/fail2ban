# quick dirty hack to avoid reading documentation for cdbs where
# install target involved only if using autotools
DESTDIR=debian/fail2ban

all:: 
	cp fail2ban.py fail2ban
	help2man -N -s 1 fail2ban >| fail2ban.1

install:: all
	mkdir -p $(DESTDIR)/etc/default
	python setup.py install --root=debian/fail2ban/
	cp config/fail2ban.conf.default $(DESTDIR)/etc/fail2ban.conf
	cp config/gentoo-confd   $(DESTDIR)/etc/default/fail2ban
	mkdir -p $(DESTDIR)/usr/lib/fail2ban/
	cp log4py.py $(DESTDIR)/usr/lib/fail2ban/

clean::
	rm -rf changelog.gz fail2ban{,.1} build* `find -iname '*.pyc' `
