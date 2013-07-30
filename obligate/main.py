import datetime
import sys
import os
import logging as log
from obligate import Obligator
from utils import loadSession


def main():
    log_format = "{} {}\t{}\t{}".format('%(asctime)s',
                                        '%(levelname)s',
                                        '%(funcName)s',
                                        '%(message)s')
    log_dateformat = '%m/%d/%Y %I:%M:%S %p'
    file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
    now = datetime.datetime.now()
    filename_format = 'logs/obligate.{}.log'\
        .format(now.strftime(file_timeformat))
    # create the logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    log.basicConfig(format=log_format,
                    datefmt=log_dateformat,
                    filename=filename_format,
                    filemode='w',
                    level=log.DEBUG)

    root = log.getLogger()
    ch = log.StreamHandler(sys.stdout)
    ch.setLevel(log.DEBUG)
    formatter = log.Formatter(log_format)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    session = loadSession()
    migration = Obligator(session)
    migration.flush_db()
    migration.migrate()
    log.info("Dumping json to file {0}...".format(migration.json_filename))
    migration.dump_json()

if __name__ == "__main__":
    main()
