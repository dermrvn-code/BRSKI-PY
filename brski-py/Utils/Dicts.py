def array_to_dict(nested_array) -> dict:
    """
    Converts a nested array into a dictionary.

    Args:
        nested_array: A nested array containing subarrays.

    Returns:
        dict: A dictionary where the first element of each subarray is used as the key and the second element is used as the value.
    """
    if nested_array == None:
        return {}

    result_dict = {}
    for subarray in nested_array:
        if len(subarray) > 0 and len(subarray[0]) == 2:
            key, value = subarray[0]
            result_dict[key] = value
    return result_dict
