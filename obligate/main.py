import argparse
from obligate import Obligator
from utils import clear_logs, loadSession, start_logging
from models import melange, neutron


def main():
    parser = argparse.ArgumentParser(description='Migrate from Melange to Quark.')  # noqa
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='Log to stdout and to file.', dest='verbose')
    parser.add_argument('-c', '--clear', action='store_true', default=False,
                        help='Clear logs before running.', dest='clearlogs')
    arguments = parser.parse_args()
    start_logging(verbose=arguments.verbose)
    if arguments.clearlogs:
        clear_logs()
    melange_session = loadSession(melange.engine)
    neutron_session = loadSession(neutron.engine)
    migration = Obligator(melange_session, neutron_session)
    migration.flush_db()
    migration.migrate()

if __name__ == "__main__":
    main()
