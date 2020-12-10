if __name__ == "__main__":
    print('This script contains only functions for use in other scripts. Do not call it directly.')
    exit(1)

import sys
import time

#WARNING: A pymongo MongoClient must be initialized within each process if using multiprocessing.


try:
    import pymongo
except ImportError as error:
    print('Please install pymongo.\npip install pymongo')
    exit(1)

#database variables
mongo_database = None
mongo_client = None
mongo_database_name = 'logger'

data_logger_default_collection = 'info'

printable_log_sinks = []

def close():
    global mongo_client
    if mongo_client:
        mongo_client.close()

def init(mongo_connect_string='mongodb://localhost:27017/', print_log_sinks=['info','error'], **kwargs):
    """make a connection to the Mongo database

    Args:
    str(mongo_connect_string): connection string for Mongo ('mongodb://somehost:someport/')
    ['print_log_sinks',...]: list of log sink strings to print to console *AND* log to db (['info','error'])
    str(**database): database name/key
    
    
    Return:
    bool: on successful/failed connection
    """

    global mongo_database
    global mongo_client
    global mongo_database_name
    global printable_log_sinks

    printable_log_sinks = print_log_sinks
    
    if 'database' in kwargs.keys():
        mongo_database_name = kwargs.get('database')    
    try:
        mongo_client = pymongo.MongoClient(mongo_connect_string)
    except ConnectionError as e:
        sys.stderr.write(str(e))
        return False
    except:
        return False
    try:
        mongo_database = mongo_client[mongo_database_name]
    except:
        return False
    return True

def list_log_collections():
    global mongo_database 
    return mongo_database.list_collection_names()

def timestamp():
    t = time.gmtime()
    return {'zone': t.tm_zone, 'year': t.tm_year, 'month': t.tm_mon, 'day': t.tm_mday, 'hour': t.tm_hour, 'minute': t.tm_min, 'second': t.tm_sec}

def log(identifier, data_object, log_sink="info"):
    global mongo_database
    global printable_log_sinks
    time_stamp=timestamp()
    mongo_database[log_sink].insert_one({'timestamp': time_stamp, 'identifier':identifier, 'data': data_object})
    if log_sink in printable_log_sinks:
        print(str(time_stamp['year']) + '-' + str(time_stamp['month']).rjust(2,'0') + '-' +  str(time_stamp['day']).rjust(2,'0') + '-' +  str(time_stamp['hour']).rjust(2,'0') + ':' +  str(time_stamp['minute']).rjust(2,'0') + ':' + str(time_stamp['second']).rjust(2,'0') +  ' - ' + log_sink + ' - ' + str(identifier) + ' - ' + str(data_object))
