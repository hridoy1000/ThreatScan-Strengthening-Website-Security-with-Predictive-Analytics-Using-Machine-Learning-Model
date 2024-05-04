import requests
import hashlib
from enum import Enum
import datetime

# from bot.bots.recapthca import recapcha
import os
import logging
import uuid
import time
import urllib
import urllib.parse
import re
import traceback




# from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# from http_request_randomizer.requests.proxy.requestProxy
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager




CHROMEDRIVER = "C:\Drivers\chromedriver-win64\chromedriver.exe"

class BaseServices(Enum):
    INSTAGRAM_PC = "INSTAGRAM_PC"


class BaseBot:
    TIME_INTERVAL_EACH_SITE = 0.25
    TIME_INTERVAL_BASE = 0.5
    TIME_INTERVAL_EACH_SITE_ADDITIONAL = 0.1
    TIME_INTERVAL_COMPREHEND = 1.0

    XPATH_SITE_URL = ""
    XPATH_SITE_TITLE = ""
    XPATH_SITE_DESCRIPTION = ""
    XPATH_SUGGESTION_KEYWORD_PC = ""
    XPATH_SUGGESTION_INPUT = ""

    def __init__(self, parameters, *args, **kwargs):
       
        self.parameters = parameters
        
        self.service = kwargs.get("service", None)
        self.friends_story_data = []
        

    def init_driver_local_chrome(self):
        self.mobile = False
        self.FORCE_HEADLESS = True
        options = webdriver.ChromeOptions()
        options.add_experimental_option("detach",True)
        self.driver = webdriver.Chrome(options=options,service= Service(ChromeDriverManager().install()))

    def _get_option_chrome_default(self):
        options = Options()
        options.add_argument("--remote-debugging-port=0")
        # options.add_argument('--headless')
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--single-process")
        options.add_argument("--incognito")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-dev-shm-usage")

        options.add_argument("--disable-features=VizDisplayCompositor")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")

        if self.FORCE_HEADLESS or self.headless == 0:
            options.add_argument("--headless")

        return options

    def _get_option_chrome_headless(self):
        options = self._get_option_chrome_default()
        options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
        )

        return options


    def close(self):
        self.driver.close()

    def quit(self):
        self.driver.quit()

    def _delete_local_storage(self):
        self.driver.execute_script("window.localStorage.clear();")

    def _send_keys(self, element, key, count=1):
        try:
            element.send_keys(key)
        except Exception as e:
            raise e

    def _get(self, URL, count=1):
        try:
            self.driver.get(URL)
        except Exception:
            print(traceback.format_exc())


    def _set_window_size(self):
        self.driver.set_window_size(1200, 5000)
        time.sleep(self.TIME_INTERVAL_BASE)
        



    