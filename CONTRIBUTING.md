Guidelines on Fail2Ban contributions
====================================

### You found a severe security vulnerability in Fail2Ban?
email details to fail2ban-vulnerabilities at lists dot sourceforge dot net .

### You need some new features, you found bugs?
visit [Issues](https://github.com/fail2ban/fail2ban/issues)
and if your issue is not yet known -- file a bug report. See
[Fail2Ban wiki](http://www.fail2ban.org/wiki/index.php/HOWTO_Seek_Help)
on further instructions.

### You would like to troubleshoot or discuss?
join the [mailing list](https://lists.sourceforge.net/lists/listinfo/fail2ban-users)

### You would like to contribute (new filters/actions/code/documentation)?
send a [pull request](https://github.com/fail2ban/fail2ban/pulls)

Pull requests guidelines
========================

- If there is an issue on github to be closed by the pull request, include
  ```Closes #ISSUE``` (where ISSUE is issue's number)
  
- Add a brief summary of the change to the ChangeLog file into a corresponding
  section out of Fixes, New Features or Enhancements (improvements to existing
  features)
