# README #

Tool for creation of fail2ban filters with regexes  and such, so that we dont need to get frustrated about that anymore


### How do I get set up? ###



## Installation

To install globally, run

	$ python setup.py install

Then 'failregexmaker' will be installed as a global command:

	$ failregexmaker my_logs

If you don't want to do that, just make sure 'six' is installed with 

	$ pip install six

Then you can run

	$ python regex_maker.py my_logs


## Operation

failregexmaker takes a single argument: the location of a log file.

Operation works as follows:

	0. You are building a failregex, one line at a time
	1. You are asked to enter some strings to match against. You will be shown suggestions
	2. Type the number of a suggestion, or press 'm' to type your own, or press 'm' to continue (from 5.)
	3. You will have the opportunity to modify the suggestion
	4. Go back to (2.)
	5. At this point there is a check to see if your first log line contains multiple hosts. If it does, enter the number of the host you want to replace with <HOST>
	6. If the failregex matches everything in your log file, quit, otherwise...
	7. If it does not match anything, start building the next line and go to 1.

## Limitations

The program assumes that all log entries in a single file have the same number of IP addresses present.
