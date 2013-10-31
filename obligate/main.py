import argparse
from obligate import Obligator
from utils import loadSession, logit
from models import melange, neutron


def main():
    verbose = False
    parser = argparse.ArgumentParser(description='Migrate from Melange to Quark.')  # noqa
    parser.add_argument('-v', dest='verbose', action='store_true',
                        default=False, help='Log to stdout.')
    parser.parse_args()
    log = logit('obligate.main', verbose)
    melange_session = loadSession(melange.engine)
    neutron_session = loadSession(neutron.engine)
    migration = Obligator(melange_session, neutron_session)
    migration.flush_db()
    migration.migrate()

if __name__ == "__main__":
    main()
