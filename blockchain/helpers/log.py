import logging


logger = logging.getLogger("logger")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler("app.log")
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.ERROR)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)
