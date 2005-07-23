# quick dirty hacks
#
DESTDIR=debian/fail2ban

all:: fail2ban.1x


fail2ban.1x: fail2ban fail2ban.h2m
	help2man --include fail2ban.h2m --section=1x --no-info --output $@ ./fail2ban

install:: all
	python setup.py install --root=debian/fail2ban/

clean::
	rm -rf changelog.gz fail2ban.1x build* `find -iname '*.pyc' `
