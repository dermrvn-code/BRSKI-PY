import json

from art import tprint
from colorama import Fore, Style
from pygments import formatters, highlight, lexers


def prettyprint_json(data, shorten=False, shorten_longer_than=35):
    """
    Pretty prints JSON data with optional shortening of long string values.

    Args:
        data (dict or str): The JSON data to be pretty printed. It can be either a dictionary or a JSON string.
        shorten (bool): Whether to shorten long string values. Defaults to False.
        shorten_longer_than (int): The length threshold for shortening string values. Defaults to 35.

    Returns:
        None

    Raises:
        ValueError: If the data is not a dictionary or a JSON string.
    """

    if type(data) is dict:
        dictionary = data
    elif type(data) is str:
        dictionary = json.loads(data)
    else:
        raise ValueError("Data must be a dictionary or a JSON string")

    if shorten:
        for key, value in dictionary.items():
            if isinstance(value, str) and len(value) > shorten_longer_than:
                dictionary[key] = value[:shorten_longer_than] + "..."

    formatted_json = json.dumps(dictionary, sort_keys=True, indent=4)
    colorful_json = highlight(
        formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter()
    )
    print(colorful_json)


def print_title(title: str) -> None:
    """
    Prints a title with a line above and below it.

    Args:
        title (str): The title to be printed.

    Returns:
        None
    """

    tprint(title, font="cybermedium")


def print_colorful(str: str | tuple[str, ...], color: str, sep: str = " ") -> None:
    """
    Prints a string in a specified color.

    Args:
        str (str): The strings to be printed.
        color (str): The color to be used.
        sep (str): The separator between the strings. Defaults to ' '.

    Returns:
        None
    """

    print(f"{color}{sep.join(str)}{Style.RESET_ALL}")


def print_error(*errors: str, sep: str = " ") -> None:
    """
    Prints error messages.

    Args:
        *errors (str): The error messages to be printed.
        sep (str): The separator between the error messages. Defaults to ' '.

    Returns:
        None
    """

    print_colorful(errors, color=Fore.RED, sep=sep)


def print_success(*successes: str, sep: str = " ") -> None:
    """
    Prints success messages.

    Args:
        *successes (str): The success messages to be printed.
        sep (str): The separator between the success messages. Defaults to ' '.

    Returns:
        None
    """

    print_colorful(successes, color=Fore.GREEN, sep=sep)


def print_warning(*warnings: str, sep: str = " ") -> None:
    """
    Prints warning messages.

    Args:
        *warnings (str): The warning messages to be printed.
        sep (str): The separator between the warning messages. Defaults to ' '.

    Returns:
        None
    """

    print_colorful(warnings, color=Fore.YELLOW, sep=sep)


def print_info(*infos: str, sep: str = " ") -> None:
    """
    Prints info messages.

    Args:
        *infos (str): The info messages to be printed.
        sep (str): The separator between the info messages. Defaults to ' '.

    Returns:
        None
    """

    print_colorful(infos, color=Fore.CYAN, sep=sep)


def print_descriptor(*descriptors: str, sep: str = " ") -> None:
    """
    Prints descriptors.

    Args:
        *descriptors (str): The descriptors to be printed.
        sep (str): The separator between the descriptors. Defaults to ' '.

    Returns:
        None
    """

    print_colorful(descriptors, color=Fore.LIGHTCYAN_EX, sep=sep)
