#!/usr/bin/env python

from __future__ import print_function
import argparse
import sys
from itertools import chain
try:
    from regexmaker.lib.common_substrings import common_substrings, single_line_suggestion
    from regexmaker.lib.input_default import input, input_int_or_str, input_int
    from regexmaker.lib.regexmaker import RegexMaker
except ImportError:
    from lib.common_substrings import common_substrings, single_line_suggestion
    from lib.input_default import input, input_int_or_str, input_int
    from lib.regexmaker import RegexMaker

class InteractiveMaker(object):
    def __init__(self, logs):
        self.logs = [x for x in logs.split('\n') if x.strip()]
        self.state = 'GET_STRINGS'
        self.regexmaker = RegexMaker(self.logs)
    
    def get_strings(self):
        if len(self.logs) > 1:
            print("Here is an example log")
        else:
            print("Here is your log line")
        print(self.regexmaker.get_preview_log())

        print()
        print("Which strings do you want to match on?")
        self.state = 'GET_STRING_WITH_SUGGESTIONS'

    def get_more_strings(self):
        print("You're currently looking for: ")
        for s in self.regexmaker.get_strings():
            print(" - {}".format(s))
        print()
        print("Do you want to match on anything else?")
        self.state = 'GET_STRING_WITH_SUGGESTIONS'

    def get_all_suggestions(self):
        if len(self.logs) == 1:
            return common_substrings(self.logs)
        else:
            common_substring_suggestions = single_line_suggestion(self.logs[0])
            single_log_suggestions = list(chain.from_iterable([single_line_suggestion(x) for x in self.logs]))
            return sorted(list(set(common_substring_suggestions + single_log_suggestions)))

    def get_string_with_suggestions(self):
        suggestions = self.get_all_suggestions()

        if len(suggestions) > 0:
            print("Here are some suggestions:")
        else:
            print("No suggestions found. What would you like to do?")
        for i, s in enumerate(suggestions):
            print("{}: {}".format(i, s))
        print('m: Custom entry')
        print('q: Done')
        print()
        print("Type a number to select and edit one, press enter to input manually.")
        self.state = 'GET_STRING'

    def get_string(self):
        suggestions = self.get_all_suggestions()

        suggestion = None
        t, v = input_int_or_str("Option> ", expected_range=(0, len(suggestions)-1))
        if v == 'q':
            self.state = 'TEST_FAILREGEX'
            return
        elif v == 'm':
            pass
        elif t == 'int':
            suggestion = suggestions[v]
        else:
            print("Invalid option")
            self.state = 'GET_STRING'
            return
        string = input("Search for> ", default=suggestion)
        print()
        self.regexmaker.add_string(string)
        self.state = 'GET_MORE_STRINGS'


    def print_current_regex(self, final=False):
        if final: 
            print("Your final regex is:")
        else:
            print("Your regex currently looks like this:")
        print()
        print(self.regexmaker.get_full_failregex())

    def test_failregex(self):
        if self.regexmaker.test_failregexes():
            self.state = 'CHECK_HOSTS'
        else:
            self.print_current_regex()
            print()
            print("This regex does not match all the logs in your log file, so you need to add additional lines.")
            print("Do you want to continue? ([y]/n)")
            response = input()
            if response.lower() != 'n':
                self.regexmaker.start_new_strings_set()
                self.state = 'GET_STRINGS'
            else:
                self.state = 'EXIT'



    def check_hosts(self):
        n_hosts = self.regexmaker.count_hosts()
        if n_hosts > 1:
            print("The first log contains {} possible <HOST>s".format(n_hosts))
            print("You need to pick one to be the actual <HOST>")
            print("Which one would you like to pick? (first = 1, last = {})".format(n_hosts))
            print()
            print("To remind you, here is your first log line: ")
            print("    {}".format(self.logs[0]))
            n = input_int(expected_range=(1, n_hosts))
            self.regexmaker.host_number = n
        self.state = 'PREVIEW_REGEX'

    def preview_regex(self):
        self.print_current_regex()
        print()
        print("This regex successfully matches all logs in the file")

        self.state = 'EXIT'

    def run(self):
        while self.state != 'EXIT':
            getattr(self, self.state.lower())()
            print()
        self.print_current_regex(final=True)


def main():
    parser = argparse.ArgumentParser(description='Interactively build failregex strings from log files')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'))
    args = parser.parse_args()
    if not args.infile:
        print("Enter log line")
        log_input = input(">")
    else:
        log_input = args.infile.read()
        args.infile.close()
    maker = InteractiveMaker(log_input)
    maker.run()

if __name__ == '__main__':
    main()

