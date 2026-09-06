"""Stable native build identity, excluding diagnostic paths and host labels."""
import hashlib
import json


def build_identity(receipt):
    """Binary bytes and immutable source/build inputs define compatibility."""
    if type(receipt.get('schema')) is not int or receipt['schema'] != 1:
        raise ValueError('Unsupported native build receipt schema')
    fields = ('backend', 'sourceRevision', 'sourceArchiveSha256', 'patchSha256',
              'sources', 'builderSha256', 'binarySha256')
    identity = {'schema': 'ghigbc-native-build-v1'}
    for field in fields:
        identity[field] = receipt[field]
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
