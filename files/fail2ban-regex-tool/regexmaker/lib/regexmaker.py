import re
from functools import partial
IP_REGEX = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})(\b|^)";
IP_BACK_REGEX = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})\\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})(\b|^)";



def replace_hosts_with_placeholders(log, n=2):
    # Find hosts in the log string to replace with "<HOST>"
    i = [0]
    def replace_func(matchobj):
        i[0]+=1
        if i[0] == n:
            return '<HOST>'
        else:
            return '\S+'

    return re.sub(IP_BACK_REGEX, replace_func, log)

def remove_all_except_important_tokens(log, important_strings):
    # Remove things from the log which we don't care about
    tokens = [re.escape(s) for s in important_strings] + [IP_REGEX]
    # tokens += ['\[', '\]']
    regex = r"^(.*?)(" + "|".join(tokens) + ")"
    out = []
    match = re.match(regex, log)
    while match:
        out.append(re.escape(match.group(2)))
        log = log[len(match.group(0)):]
        match = re.match(regex, log)
    
    return ".*".join(out)

def test_failregex(log, regex):
    # Replace <HOST> with the host regex as specified in failregex documentation
    failregex = regex.replace('<HOST>', "(?:::f{4,6}:)?(\S+)")
    return re.search(failregex, log)

def process_log(log, important_strings, host_number=1):
    # Build a regex string which will match a log string
    log = remove_all_except_important_tokens(log, important_strings)
    log = replace_hosts_with_placeholders(log, host_number)
    log = log.replace('\ ', ' ')
    
    return log

def count_hosts(log, important_strings):
    """ Count the number of ips in a log file (after processing) """
    log = remove_all_except_important_tokens(log, important_strings)
    return len(re.findall(IP_BACK_REGEX, log))
    

class RegexMaker(object):
    """ RegexMaker lets you build up the information required to create custom failregex strings from logs. """
    def __init__(self, logs):
        self.strings = [[]]
        self.logs = logs
        self.host_number = 1
        self.host_number_set = False
        self.current_string_set = 0
        self.log_to_preview = 0

    def set_host_number(self, n):
        """ Specify that, for the logs we have, the ip to replace with "<HOST>" is the 'n'th IP """
        self.host_number = n
        self.host_number_set = True

    def start_new_strings_set(self):
        """ Start building another line of the failregex """
        self.strings.append([])
        self.current_string_set += 1

    def get_strings(self, i=None):
        """ Get the 'strings to find' for the failregex line currently being built (or, a specific one) """
        if i is None:
            i = self.current_string_set
        return self.strings[i]

    def add_string(self, string, i=None):
        """ Add a 'string to find' for the failregex line currently being built (or, a specific one) """
        if i is None:
            i = self.current_string_set
        if string.strip():
            self.strings[i].append(string.strip())

    def get_preview_log(self):
        """ Get either the first log line, or the last line that failed to match when we ran test_failregexes() """
        return self.logs[self.log_to_preview]

    def get_full_failregex(self):
        """ Print out the full failregex representation """
        out_lines = set()
        for log in self.logs:
            for i in range(len(self.strings)):
                if self.test_failregex(log, i):
                    # out_lines.add(process_log(log, self.strings[i], host_number=self.host_number))
                    out_lines.add(self.get_failregex(log, i))
                    break
        return "failregex = " + "\n    ".join(list(out_lines))



    def get_failregex(self, log, i=None):
        """ Create a failregex line based on a specific log line and the ith set of 'strings to find' """
        if i is None:
            i = self.current_string_set
        return process_log(log, self.strings[i], host_number=self.host_number)

    def count_hosts(self, i=0):
        """ Count the number of host IPs in the first log line """
        if not i:
            i = self.current_string_set
        return count_hosts(self.logs[0], self.strings[i])

    def test_failregex(self, log, i):
        """ For a given log line and set of 'strings to find', create the fail regex then see if it actually matches the log.
                If the created failregex is empty or just '<HOST>', that also counts as a failure.
        """
        regex = self.get_failregex(log, i=i)
        if regex.replace('<HOST>', '').strip() == '':
            return False
        failregex = regex.replace('<HOST>', "(?:::f{4,6}:)?(?P<host>\S+)")
        if re.search(failregex, log):
            return True
        else:
            return False

    def test_failregexes(self):
        """ Given the current full set of failregexes, see if they would match all log lines. 
        If they would not, set self.log_to_preview to be the index of the log line which is not matched. """
        for i, log in enumerate(self.logs):
            passed = False
            for k in range(len(self.strings)):
                if self.test_failregex(log, k):
                    passed = True
                    continue
            if passed == False:
                self.log_to_preview = i
                return False
        return True

        