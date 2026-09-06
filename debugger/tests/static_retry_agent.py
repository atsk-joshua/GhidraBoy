"""Test-only real RMI producer: reject one upload before calling production code."""
from dataclasses import replace
from ghigbc.agent import Agent, main

original = Agent.remotes


def remotes(self):
    original(self)
    method = self.registry._methods['static_mapping']
    failed = False

    def transfer(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            print('INJECTED_STATIC_TRANSFER_FAILURE', flush=True)
            raise RuntimeError('Test-only transient static transfer failure')
        return method.callback(*args, **kwargs)

    self.registry.register_method(replace(method, callback=transfer))


Agent.remotes = remotes
main()
