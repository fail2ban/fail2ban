import readline
from six.moves import input as input_old

def default_hook():
    """Insert some default text into the raw_input."""
    readline.insert_text(default_hook.default_text)
    readline.redisplay()
readline.set_pre_input_hook(default_hook)

def input(prompt='>', default=None):
    """Take raw_input with a default value."""
    default_hook.default_text = '' if default is None else default
    return input_old(prompt)


def input_int_or_str(prompt='>', expected_range=None, default=None):
    """ Prompt the user for either a string, or an int (possibly enforced within a range).
        Return a tuple of (type, value) 
    """
    while True:
        value = input(prompt, default)
        try:
            v = int(value.strip())
            if expected_range and (v < expected_range[0] or v > expected_range[1]):
                print("Please only enter numbers between {} and {}".format(*expected_range))
                continue
            return ('int', v)
        except ValueError:
            return ('str', value)


def input_int(prompt='>', expected_range=None, default=None):
    """ Prompt the user for an int (possibly enforced within a range) until they give a valid one """
    while True:
        value = input(prompt, default)
        try:
            v = int(value.strip())
            if expected_range and (v < expected_range[0] or v > expected_range[1]):
                print("Please enter a number between {} and {}".format(*expected_range))
                continue
            return v
        except ValueError:
            print("Invalid value. Enter a valid number")
            continue