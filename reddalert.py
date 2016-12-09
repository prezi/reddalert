#!/usr/bin/env python
import json
import time
import calendar
import argparse
import logging
import sys

from lockfile import LockFile, LockTimeout

from api import EddaClient, Coordinator, Alerter
from plugins import plugin_list


class Reddalert:
    def __init__(self, logger):
        self.logger = logger

    @staticmethod
    def get_since(since):
        if since:
            try:
                # return UTC timestamp in milliseconds
                # TODO: support millisecond string format as well?
                return calendar.timegm(time.strptime(since, "%Y-%m-%d %H:%M:%S")) * 1000
            except ValueError:
                if since.isdigit():
                    # consider it as an epoch timestamp
                    return int(since)
            except:
                pass
        return None

    @staticmethod
    def load_json(json_file, logger):
        if json_file is not None:
            try:
                with open(json_file, 'r') as config_data:
                    return json.load(config_data)
            except IOError:
                logger.exception("Failed to read file '%s'", json_file)
            except ValueError:
                logger.exception("Invalid JSON file '%s'", json_file)
        return {}

    @staticmethod
    def save_json(json_file, content, logger):
        if not content:
            logger.warning('Got empty JSON content, not updating status file!')
            return

        if json_file is not None:
            try:
                with open(json_file, 'w') as out_data:
                    json.dump(content, out_data, indent=4)
                    return True
            except IOError:
                logger.exception("Failed to write file '%s'", json_file)
        return False

    @staticmethod
    def get_config(key, config, arg=None, default=None):
        if arg is not None:
            return arg
        if key in config:
            return config[key]
        return default


if __name__ == '__main__':
    import argparse
    import logging
    from api import EddaClient, Coordinator, Alerter
    from plugins import plugin_list


    parser = argparse.ArgumentParser(description='Runs tests against AWS configuration')
    parser.add_argument('--configfile', '-c', default='etc/configfile.json', help='Configuration file')
    parser.add_argument('--statusfile', '-f', default='etc/statusfile.json', help='Persistent store between runs')
    parser.add_argument('--since', '-s', default=None,
                        help='Override statusfile, epoch in ms, Y-m-d H-M-S format or file')
    # hack to avoid race condition within EDDA: it's possible instances are synced while eg security groups aren't.
    parser.add_argument('--until', '-u', default=int(time.time()) * 1000 - 5 * 60 * 1000, help='Until, epoch in ms')
    parser.add_argument('--store-until', action="count", help='Use file in --since to store back the until epoch')
    parser.add_argument('--edda', '-e', default=None, help='Edda base URL')
    parser.add_argument('--sentry', default=None, help='Sentry url with user:pass (optional)')
    parser.add_argument('--output', '-o', default=None,
                        help='Comma sepparated list of outputs to use (stdout,stdout_tabsep,mail_txt,mail_html,elasticsearch)')
    parser.add_argument('--silent', '-l', action="count", help='Supress log messages lower than warning')
    parser.add_argument('rules', metavar='rule', nargs='*', default=plugin_list.keys(), help='Rules to check')
    args = parser.parse_args()

    root_logger = logging.getLogger()

    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s')
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    # Setup logger output
    root_logger.addHandler(ch)

    # Supress logging
    if args.silent:
        root_logger.setLevel(logging.WARNING)
    else:
        root_logger.setLevel(logging.DEBUG)

    root_logger.info('Called with %s', args)

    if args.sentry:
        from raven import Client
        from raven.handlers.logging import SentryHandler


        client = Client(args.sentry)
        handler = SentryHandler(client)
        handler.setLevel(logging.ERROR)
        root_logger.addHandler(handler)

    try:
        lock_handler = LockFile(args.statusfile)
        lock_handler.acquire(timeout=3)
        root_logger.debug("Lock file not found, creating %s.lock" % lock_handler.path)
    except LockTimeout as e:
        root_logger.critical('Locked, script running... exiting.')
        sys.exit()

    # Load configuration:
    config = Reddalert.load_json(args.configfile, root_logger)

    # Load data from previous run:
    status = Reddalert.load_json(args.statusfile, root_logger)
    since = Reddalert.get_config('since', status, Reddalert.get_since(args.since), 0)

    # Setup EDDA client
    edda_url = Reddalert.get_config('edda', config, args.edda, 'http://localhost:8080/edda')
    edda_client = EddaClient(edda_url).since(since).until(args.until)

    # Setup the alerter
    output_targets = Reddalert.get_config('output', config, args.output, 'stdout')
    alerter = Alerter(output_targets)

    # Setup the Coordinator
    coordinator = Coordinator(edda_client, alerter, config, status)

    # Run checks
    for plugin in [plugin_list[rn] for rn in args.rules if rn in plugin_list]:
        root_logger.info('run_plugin: %s', plugin.plugin_name)
        coordinator.run(plugin)

    # Send alerts
    alerter.send_alerts(config)

    # Save results
    if Reddalert.get_config('store-until', config, args.output, False):
        status['since'] = args.until
    Reddalert.save_json(args.statusfile, status, root_logger)

    root_logger.info("Reddalert finished successfully.")
    lock_handler.release()
