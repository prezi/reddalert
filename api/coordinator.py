
class Coordinator:

    def __init__(self, edda_client, alerter, config, status):
        self.edda_client = edda_client
        self.alerter = alerter
        self.status = status
        self.config = config

    def run(self, plugin):
        plugin_config = self.plugin_specific(plugin.plugin_name, self.config)
        plugin_status = self.plugin_specific(plugin.plugin_name, self.status)
        plugin.init(self.edda_client, plugin_config, plugin_status)
        results = plugin.run()
        self.alerter.run(results)

    def plugin_specific(self, plugin_name, ctx):
        search_name = "plugin." + plugin_name
        if search_name not in ctx:
            ctx[search_name] = {}
        return ctx[search_name]
