FROM python:3.10-slim

WORKDIR /root
COPY setup.py fail2ban config bin ./
RUN python setup.py install

ENTRYPOINT ["/bin/fail2ban-server"]
