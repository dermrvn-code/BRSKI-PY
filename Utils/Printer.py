import json
from pygments import highlight, lexers, formatters


def prettyprint_json(data, shorten=False, shorten_longer_than=35):
    """
    Pretty prints JSON data with optional shortening of long string values.

    Args:
        data (dict or str): The JSON data to be pretty printed. It can be either a dictionary or a JSON string.
        shorten (bool, optional): Whether to shorten long string values. Defaults to False.
        shorten_longer_than (int, optional): The length threshold for shortening string values. Defaults to 35.

    Returns:
        None

    Raises:
        ValueError: If the data is not a dictionary or a JSON string.
    """

    if(type(data) is dict):
        dictionary = data
    elif(type(data) is str):
        dictionary = json.loads(data)
    else:
        raise ValueError("Data must be a dictionary or a JSON string")

    if shorten:
        for key, value in dictionary.items():
            if isinstance(value, str) and len(value) > shorten_longer_than:
                dictionary[key] = value[:shorten_longer_than] + "..."

    formatted_json = json.dumps(dictionary, sort_keys=True, indent=4)
    colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
    print(colorful_json)
