# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

from typing import Any, AnyStr

import cysimdjson
import rapidjson

cysimdjson_parser = cysimdjson.JSONParser()


def json_dumper(json_object: Any) -> str:
    s: str = ""
    if (
        isinstance(json_object, cysimdjson.JSONObject)
        or isinstance(json_object, cysimdjson.JSONArray)
        or isinstance(json_object, cysimdjson.JSONElement)
    ):
        s = rapidjson.dumps(json_object.export())
        return s

    s = rapidjson.dumps(json_object)
    return s


def json_parser(payload: AnyStr, export: bool = True) -> Any:
    if isinstance(payload, str):
        o = cysimdjson_parser.parse(payload.encode("utf-8"))
    else:
        o = cysimdjson_parser.parse(payload)

    if export:
        return o.export()

    return o.get_value()
