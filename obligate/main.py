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

if __name__ == "__main__":
    main()
