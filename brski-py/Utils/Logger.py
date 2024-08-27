import logging
import os


class Logger:
    def __init__(
        self,
        log_file,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    ):
        # Create the log directory if it does not exist
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)

        self.log_file = log_file
        self.logger = logging.getLogger(log_file)
        self.logger.setLevel(level)

        # Prevent adding multiple handlers to the same logger
        if not self.logger.hasHandlers():
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter(format))
            self.logger.addHandler(handler)

    def log(self, message, level=logging.INFO):
        """
        Logs a message with the specified log level.

        Args:
            message (str): The message to be logged.
            level (int, optional): The log level. Defaults to logging.INFO.
        """

        self.logger.log(level, message)

    def get_log_list(self) -> list[dict]:
        """
        Parses the log file and returns a list of dictionaries containing the log records.

        Returns:
            list[dict]: A list of dictionaries containing the log records
        """

        logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                for line in f:
                    log_record = self._parse_log_line(line)
                    if log_record:
                        logs.append(log_record)
        return logs

    def _parse_log_line(self, line: str) -> dict | None:
        """
        Parses a log line and returns a dictionary containing the log record.

        Args:
            line (str): The log line to be parsed.

        Returns:
            dict | None: A dictionary containing the log record or None if the line could not be parsed.
        """

        try:
            parts = line.split(" - ")
            return {
                "time": parts[0],
                "level": parts[1],
                "message": " - ".join(parts[2:]).strip(),
            }
        except IndexError:
            return None
