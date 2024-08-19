

def yes_or_no(prompt: str) -> bool:
    """
    Display a Yes/No prompt to the user.

    Parameters:
        prompt (str): The question to prompt the user.

    Returns:
        bool: True if the user answers 'yes', False if the user answers 'no'.
    """
    while True:
        answer = input(f"{prompt} (yes/no): ").strip().lower()
        if answer in ['yes', 'y']:
            return True
        elif answer in ['no', 'n']:
            return False
        else:
            print("Please answer with 'yes' or 'no'.")