
from sshtunnel import SSHTunnelForwarder
import pymysql
import pandas as pd

tunnel = SSHTunnelForwarder(('116.254.113.64', 3512), ssh_password='P@ssw0rdm1p', ssh_username='root',
     remote_bind_address=('127.0.0.1', 3306)) 
tunnel.start()
conn = pymysql.connect(host='127.0.0.1', user='mipuser', passwd='P@ssw0rdm1p', port=tunnel.local_bind_port)
data = pd.read_sql_query("SHOW DATABASES;", conn)