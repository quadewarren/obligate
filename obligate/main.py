# import logging as log
from obligate import Obligator
from utils import loadSession, logit
from models import melange, neutron


def main():
    log = logit('obligate.main')
    melange_session = loadSession(melange.engine)
    neutron_session = loadSession(neutron.engine)
    migration = Obligator(melange_session, neutron_session)
    migration.flush_db()
    migration.migrate()
    log.info("Dumping json to file {0}...".format(migration.json_filename))
    migration.dump_json()

if __name__ == "__main__":
    main()
