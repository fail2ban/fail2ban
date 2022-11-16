---
name: Bug report
about: Report a bug within the fail2ban engines (not filters or jails)
title: '[BR]: '
labels: bug
assignees: ''

---

<!--
  - Before reporting, please make sure to search the open and closed issues for any reports in the past.
  - Use this issue template to report a bug in the fail2ban engine (not in a filter or jail).
  - If you want to request a feature or a new filter, please use "Feature request" or "Filter request" instead.
  - If you have rather some question, please open or join to some discussion.

  We will be very grateful, if your problem was described as completely as possible,
  enclosing excerpts from logs (if possible within DEBUG mode, if no errors evident
  within INFO mode), and configuration in particular of effected relevant settings
  (e.g., with ` fail2ban-client -d | grep 'affected-jail-name' ` for a particular
  jail troubleshooting).
  Thank you in advance for the details, because such issues like "It does not work" 
  alone could not help to resolve anything!
  Thanks! 
  (you can remove this paragraph and other comments upon reading)
-->

### Environment:

<!--
  Fill out and check (`[x]`) the boxes which apply. If your Fail2Ban version is outdated, 
  and you can't verify that the issue persists in the recent release, better seek support 
  from the distribution you obtained Fail2Ban from
-->

- Fail2Ban version <!-- including any possible distribution suffixes --> : 
- OS, including release name/version : 
- [ ] Fail2Ban installed via OS/distribution mechanisms
- [ ] You have not applied any additional foreign patches to the codebase
- [ ] Some customizations were done to the configuration (provide details below is so)

### The issue:

<!-- summary here -->

#### Steps to reproduce

#### Expected behavior

#### Observed behavior

#### Any additional information


### Configuration, dump and another helpful excerpts

#### Any customizations done to /etc/fail2ban/ configuration
<!-- put your configuration excerpts between next 2 lines -->
```
```

#### Relevant parts of /var/log/fail2ban.log file:
<!-- preferably obtained while running fail2ban with `loglevel = 4` -->
<!-- put your log excerpt between next 2 lines -->
```
```

#### Relevant lines from monitored log files:
<!-- put your log excerpt between next 2 lines -->
```
```
