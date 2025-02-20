import os
from dotenv import load_dotenv

load_dotenv()



ZABBIX_SERVER_6 = os.getenv('ZABBIX_SERVER_6')
ZABBIX_USER = os.getenv('ZABBIX_USER')
ZABBIX_PASSWORD = os.getenv('ZABBIX_PASSWORD')

ZABBIX_SERVER_7 = os.getenv('ZABBIX_SERVER_7')
ZABBIX_TOKEN = os.getenv('ZABBIX_TOKEN')


# ZABBIX_CREDENTIALS = {
#     "url": os.getenv('ZABBIX_SERVER_6'),
#     "user": os.getenv('ZABBIX_USER'),
#     "password": os.getenv('ZABBIX_PASSWORD')
# }

ZABBIX_CREDENTIALS = {
    "url": os.getenv('ZABBIX_SERVER_7'),
    "token": os.getenv('ZABBIX_TOKEN')
}