import re

IP_REGEX = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})(\b|^)";
IP_BACK_REGEX = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})\\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|x{1,3})(\b|^)";

def replace_host_with_placeholder(log):
	# Find hosts in the log string to replace with "<HOST>"
	return re.sub(IP_BACK_REGEX, '<HOST>', log)

def get_important_tokens():
	# Get a list of things we do care about
	# I hardcoded this for the demo!!
	# The tricky bit is going to be making this configurable, or guessed using multiple similar strings.
	return ["mdm:auth", "authentication failure", "Failed Login", "<HOST>"]

def remove_all_except_important_tokens(log):
	# Remove things from the log which we don't care about
	tokens = [re.escape(s) for s in get_important_tokens()] + [IP_REGEX]
	# tokens += ['\[', '\]']
	regex = r"^(.*?)(" + "|".join(tokens) + ")"
	out = []
	match = re.match(regex, log)
	while match:
		out.append(re.escape(match.group(2)))
		log = log[len(match.group(0)):]
		match = re.match(regex, log)
	
	return ".*".join(out)

def test_failregex(regex, log):
	# Replace <HOST> with the host regex as specified in failregex documentation
	failregex = regex.replace('<HOST>', "(?:::f{4,6}:)?(?P<host>\S+)")
	return re.search(failregex, log)

def process_log(log):
	# Build a regex string which will match a log string
	# log = remove_date(log)
	log = remove_all_except_important_tokens(log)
	log = replace_host_with_placeholder(log)
	
	return log
	

# log1 = "Feb 12 08:38:00 ShipIT-laptop1 mdm[1352]: pam_unix(mdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost= user=martin"
log2 = "2017-02-16 08:02:26 root Failed Login from: 104.xx.215.141 on: http://cont.telco.support:2030/login.php"

# regex1 = process_log(log1)
regex2 = process_log(log2)

# print(regex1)
print(regex2)

# print(test_failregex(regex1, log1) is not None)
# print(test_failregex(regex2, log2) is not None)
# print(test_failregex(regex1, log2) is None)
# print(test_failregex(regex2, log1) is None)


# When you run this, the output will be:

"""
	mdm:auth.*authentication failure
	Failed Login.*<HOST>
	True
	True
	True
	True
"""