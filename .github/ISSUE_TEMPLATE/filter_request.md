---
name: Filter request
about: Request a new jail or filter to be supported or existing filter extended with new failregex
title: '[FR]: '
labels: filter-request
assignees: ''

---

<!--
  - Before requesting, please make sure to search the open and closed issues for any requests in the past.
  - Sometimes failregex have been already requested before but are not implemented yet due to various reasons.
  - If there are no hits for your concerns, please proceed otherwise add a comment to the related issue (also if it is closed).
  - If you want to request a new feature, please use "Feature request" instead.
  - If you have rather some question, please open or join to some discussion.
-->

### Environment:

<!--
  Fill out and check (`[x]`) the boxes which apply.
-->

- Fail2Ban version <!-- including any possible distribution suffixes --> : 
- OS, including release name/version : 

#### Service, project or product which log or journal should be monitored

- Name of filter or jail in Fail2Ban (if already exists) : 
- Service, project or product name, including release name/version : 
- Repository or URL (if known) : 
- Service type : 
- Ports and protocols the service is listening : 

#### Log or journal information
<!-- Delete unrelated group -->

<!-- Log file -->

- Log file name(s) : 

<!-- Systemd journal -->

- Journal identifier or unit name : 

#### Any additional information


### Relevant lines from monitored log files:

#### failures in sense of fail2ban filter (fail2ban must match):
<!-- put your log excerpt between next 2 lines -->
```
```

#### legitimate messages (fail2ban should not consider as failures):
<!-- put your log excerpt between next 2 lines -->
```
```
