import re
import os
import time
import urllib.parse
import urllib

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.common.by import By
import pandas as pd
import math
import numpy as np
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from selenium.webdriver.common.action_chains import ActionChains

from . import BaseBot, BaseServices


class Services:
    PC = BaseServices.INSTAGRAM_PC.value


    

class urlCollectingBot(BaseBot):
    ROOT_URL = "https://www.nasa.gov/"

    def __init__(
        self, parameters, *args, **kwargs
    ):
        super(urlCollectingBot, self).__init__(
            parameters, *args, **kwargs
        )
        self.services = Services

    def fetch_url(self,URL):
        self._get(URL) 
        time.sleep(self.TIME_INTERVAL_BASE)
        all_links = self.driver.find_elements(By.TAG_NAME, "a")
        urls = [link.get_attribute("href") for link in all_links]
        return urls
        
    def get_pages(self, service):
        self.service = service

        
        data=self.fetch_url(self.ROOT_URL)
        

        
        return data

