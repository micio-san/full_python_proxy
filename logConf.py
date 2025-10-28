import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", filename="logFile.log", encoding="UTF-8")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#file loh