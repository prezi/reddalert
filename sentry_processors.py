import logging

from raven.processors import Processor


class RemoveLockProcessor(Processor):
    lock_file = None

    def process(self, data, **kwargs):
        level_name = 'FATAL' if data.get('level', 0) == 'fatal' else logging.getLevelName(data.get('level', 0))

        if not RemoveLockProcessor.lock_file or not RemoveLockProcessor.lock_file.is_locked():
            return data

        if level_name == 'FATAL':
            RemoveLockProcessor.lock_file.break_lock()
            logging.getLogger().info("Sentry caught a %s message - lock file removed", level_name)
        else:
            logging.getLogger().info("Sentry caught a %s message - lock file WAS NOT removed", level_name)

        return data
