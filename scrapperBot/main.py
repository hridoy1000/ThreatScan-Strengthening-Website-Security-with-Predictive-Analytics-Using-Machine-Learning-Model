
## rinning bot

from bots.urlCollectingBot import urlCollectingBot
import requests
import json
import csv
import pandas as pd

service = "urlCollectingBot"
parameters = {
          
            
        }

urlCollectingBot = urlCollectingBot(
    parameters = parameters,
)

urlCollectingBot.init_driver_local_chrome()

data=urlCollectingBot.get_pages(service=service)

urlCollectingBot.close()
urlCollectingBot.quit()

df = pd.DataFrame(data, columns=['url'])
df = df.dropna()

df.to_csv('urls.csv', index=False)

