# import logging as log
from obligate import Obligator
from utils import loadSession, logit


def main():
    log = logit('obligate.main')
    session = loadSession()
    migration = Obligator(session)
    migration.flush_db()
    migration.migrate()
    log.info("Dumping json to file {0}...".format(migration.json_filename))
    migration.dump_json()

if __name__ == "__main__":
    main()
