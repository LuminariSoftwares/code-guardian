from typing import TYPE_CHECKING

VALUE = 1

try:
    import ujson as fast_json
except ImportError:
    fast_json = None

if TYPE_CHECKING:
    import pandas
