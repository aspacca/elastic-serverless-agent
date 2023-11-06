# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

import base64
import random
import string
from typing import Any, AnyStr, Callable, Optional

import cysimdjson
import mock
import orjson
import pytest
import pytest_benchmark.fixture
import rapidjson
import simdjson
import simplejson
import ujson

from share import CountMultiline, ExpandEventListFromField, PatternMultiline, ProtocolMultiline, WhileMultiline
from storage import PayloadStorage

_LENGTH_1M: int = 1024**2
_LENGTH_BELOW_THRESHOLD: int = 40
_LENGTH_ABOVE_THRESHOLD: int = 1024 * 100
_LENGTH_FOR_BENCHMARK: int = 1000 # benchmark should not hit circuit breaker

_IS_PLAIN: str = "_IS_PLAIN"
_IS_JSON: str = "_IS_JSON"
_IS_JSON_LIKE: str = "_IS_JSON_LIKE"
_IS_MULTILINE_COUNT: str = "_IS_MULTILINE_COUNT"
_IS_MULTILINE_PATTERN: str = "_IS_MULTILINE_PATTERN"
_IS_MULTILINE_WHILE: str = "_IS_MULTILINE_WHILE"

cysimdjson_parser = cysimdjson.JSONParser()
pysimdjson_parser = simdjson.Parser()


def json_parser_cysimdjson(payload: AnyStr, export: bool = True) -> Any:
    if isinstance(payload, str):
        o = cysimdjson_parser.parse(payload.encode("utf-8"))
    else:
        o = cysimdjson_parser.parse(payload)

    if export:
        return o.export()

    return o.get_value()


def json_dumper_cysimdjson(json_object: Any) -> str:
    if (
        isinstance(json_object, cysimdjson.JSONObject)
        or isinstance(json_object, cysimdjson.JSONArray)
        or isinstance(json_object, cysimdjson.JSONElement)
    ):
        return rapidjson.dumps(json_object.export())

    return rapidjson.dumps(json_object)


def json_parser_pysimdjson(payload: bytes, export: bool = True) -> Any:
    return pysimdjson_parser.parse(payload)


def json_dumper_pysimdjson(json_object: Any) -> str:
    if isinstance(json_object, simdjson.Array):
        return json_object.mini.decode("utf-8")

    if isinstance(json_object, simdjson.Object):
        return json_object.mini.decode("utf-8")

    return rapidjson.dumps(json_object)


def get_by_lines_parameters() -> list[tuple[int, str, bytes]]:
    parameters: list[Any] = []
    for length_multiplier in [_LENGTH_BELOW_THRESHOLD, _LENGTH_ABOVE_THRESHOLD]:
        for content_type in [
            _IS_PLAIN,
            _IS_JSON,
            _IS_JSON_LIKE,
            _IS_MULTILINE_COUNT,
            _IS_MULTILINE_PATTERN,
            _IS_MULTILINE_WHILE,
        ]:
            for newline in [b"", b"\n", b"\r\n"]:
                for json_content_type in [None, "single", "ndjson", "disabled"]:
                    parameters.append(
                        pytest.param(
                            length_multiplier,
                            content_type,
                            newline,
                            json_content_type,
                            id=f"newline length {len(newline)} for content type {content_type} "
                            f"with length multiplier {length_multiplier} and `json_content_type` {json_content_type}",
                        )
                    )

    return parameters


def multiline_processor(content_type: str) -> Optional[ProtocolMultiline]:
    processor: Optional[ProtocolMultiline] = None
    if content_type == _IS_MULTILINE_COUNT:
        processor = CountMultiline(count_lines=3)
    elif content_type == _IS_MULTILINE_PATTERN:
        processor = PatternMultiline(pattern="MultilineStart", match="after", negate=True, flush_pattern="\\\\$")
    elif content_type == _IS_MULTILINE_WHILE:
        processor = WhileMultiline(pattern="MultilineStart", negate=True)

    return processor


class MockContentBase:
    f_size_gzip: int = 0
    f_size_plain: int = 0
    f_content_gzip: bytes = b""
    f_content_plain: bytes = b""

    mock_content: bytes = b""

    @staticmethod
    def init_content(
        content_type: str,
        newline: bytes,
        length_multiplier: int = _LENGTH_ABOVE_THRESHOLD,
        json_content_type: Optional[str] = None,
    ) -> None:
        if len(newline) == 0:
            if content_type == _IS_JSON:
                mock_content = (
                    b"{"
                    + newline
                    + b'"'
                    + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 4))).encode(
                        "utf-8"
                    )
                    + b'"'
                    + newline
                    + b":"
                    + newline
                    + b'"'
                    + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 4))).encode(
                        "utf-8"
                    )
                    + b'"'
                    + newline
                    + b"}"
                )
            elif content_type.startswith("_IS_MULTILINE"):
                mock_content = (
                    b"MultilineStart"
                    + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20))).encode(
                        "utf-8"
                    )
                    + b"\\"
                )
            else:
                mock_content = "".join(
                    random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20))
                ).encode("utf-8")
        else:
            if content_type == _IS_JSON:
                # every json entry is from 14 to 39 chars, repeated for half of length_multiplier
                mock_content = newline.join(
                    [
                        b"{"
                        + newline
                        + b'"'
                        + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 5))).encode(
                            "utf-8"
                        )
                        + b'"'
                        + newline
                        + b":"
                        + newline
                        + b'"'
                        + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 5))).encode(
                            "utf-8"
                        )
                        + b'"'
                        + newline
                        + b"}"
                        + newline
                        for _ in range(1, int(length_multiplier / 2))
                    ]
                )
            elif content_type.startswith("_IS_MULTILINE"):
                # every line is from 0 to 20 chars, repeated for length_multiplier
                mock_content = newline.join(
                    [
                        b"MultilineStart"
                        + newline
                        + "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(0, 20))).encode(
                            "utf-8"
                        )
                        + newline
                        + b"\\\\"
                        for _ in range(1, length_multiplier)
                    ]
                )
            else:
                # every line is from 0 to 20 chars, repeated for length_multiplier
                mock_content = newline + newline.join(
                    [
                        "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(0, 20))).encode(
                            "utf-8"
                        )
                        for _ in range(1, length_multiplier)
                    ]
                )

        if content_type == _IS_JSON_LIKE:
            mock_content = b"{" + mock_content

        if content_type == _IS_JSON and json_content_type == "ndjson":
            mock_content = mock_content.replace(newline + b"{", b"{").replace(b"{" + newline, b"{")
            mock_content = mock_content.replace(newline + b":", b":").replace(b":" + newline, b":")
            mock_content = mock_content.replace(newline + b'"', b'"').replace(b'"' + newline, b'"')
            mock_content = mock_content.replace(newline + b"}", b"}")

        if content_type == _IS_JSON and json_content_type == "single":
            mock_content = mock_content.replace(b"}" + newline + newline + b"{" + newline, newline + b"," + newline)

        MockContentBase.mock_content = mock_content


class Setup:
    expanded_offset: int = -1

    @staticmethod
    def setup(json_content_type: Optional[str]) -> None:
        if len(MockContentBase.mock_content) == 0:
            MockContentBase.init_content(
                content_type=_IS_JSON, newline=b"\n", length_multiplier=_LENGTH_FOR_BENCHMARK, json_content_type=json_content_type
            )

        if Setup.expanded_offset == -1:
            # -1 for `"pleaseExpand":`, -1 returning at least one event
            total_events: int = MockContentBase.mock_content.count(b":") - 2

            Setup.expanded_offset = random.randint(int(total_events / 2), total_events)


def wrap(payload: str, json_content_type: Optional[str] = None, expand: bool = False) -> int:
    expander: Optional[ExpandEventListFromField] = None
    if expand:

        def resolver(_: str, field_to_expand_event_list_from: str) -> str:
            return field_to_expand_event_list_from

        expander = ExpandEventListFromField("pleaseExpand", "", resolver, None, Setup.expanded_offset)

    payload_storage = PayloadStorage(
        payload=payload, json_content_type=json_content_type, event_list_from_field_expander=expander
    )
    lines = payload_storage.get_by_lines(range_start=0)
    last_length: int = 0
    for line in lines:
        last_length = line[2]

    return last_length


json_parser_params = [
    pytest.param(json_parser_cysimdjson, id="cysimdjson"),
    pytest.param(lambda x, _: orjson.loads(x), id="orjson"),
    pytest.param(json_parser_pysimdjson, id="pysimdjson"),
    pytest.param(lambda x, _: rapidjson.loads(x), id="rapidjson"),
    pytest.param(lambda x, _: simplejson.loads(x), id="simplejson"),
    pytest.param(lambda x, _: ujson.loads(x), id="ujson"),
]

json_parser_and_dumper_params = [
    pytest.param(json_parser_cysimdjson, json_dumper_cysimdjson, id="cysimdjson"),
    pytest.param(lambda x, _: orjson.loads(x), lambda x: orjson.dumps(x).decode("utf-8"), id="orjson"),
    pytest.param(json_parser_pysimdjson, json_dumper_pysimdjson, id="pysimdjson"),
    pytest.param(lambda x, _: rapidjson.loads(x), lambda x: rapidjson.dumps(x), id="rapidjson"),
    pytest.param(lambda x, _: simplejson.loads(x), lambda x: simplejson.dumps(x), id="simplejson"),
    pytest.param(lambda x, _: ujson.loads(x), lambda x: ujson.dumps(x), id="ujson"),
]

Setup.setup("ndjson")  # We generate an ndjson


@pytest.mark.benchmark(group="real content: plaintext, json_content_type: None")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_plain_none(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = MockContentBase.mock_content[1:]  # we reduce ndjson to plaintext
        last_length = benchmark.pedantic(
            wrap, [base64.b64encode(original).decode("utf-8"), None], iterations=100, rounds=10
        )
        original_length: int = len(original)

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: plaintext, json_content_type: disabled")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_plain_disabled(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = MockContentBase.mock_content[1:]  # we reduce ndjson to plaintext
        last_length = benchmark.pedantic(
            wrap, [base64.b64encode(original).decode("utf-8"), "disabled"], iterations=100, rounds=10
        )
        original_length: int = len(original)

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: single json, json_content_type: None")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_json_none(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = MockContentBase.mock_content.replace(
            b"}\n{", b"\n,\n"
        )  # we reduce ndjson to single
        encoded: str = base64.b64encode(original).decode("utf-8")
        last_length = benchmark.pedantic(wrap, [encoded, None], iterations=100, rounds=10)
        original_length: int = len(original)
        if original.endswith(b"\n" * 2):
            original_length -= 2

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: single json, json_content_type: single")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_json_single(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = MockContentBase.mock_content.replace(
            b"}\n{", b"\n,\n"
        )  # we reduce ndjson to single
        encoded: str = base64.b64encode(original).decode("utf-8")
        last_length = benchmark.pedantic(wrap, [encoded, "single"], iterations=100, rounds=10)
        original_length: int = len(original)
        if original.endswith(b"\n" * 2):
            original_length -= 2

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: json like, json_content_type: None")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_json_like_none(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = (
            b"{" + MockContentBase.mock_content
        )  # we reduce json like (ie: {{"this": "seems", "a: "json"})
        encoded: str = base64.b64encode(original).decode("utf-8")
        last_length = benchmark.pedantic(wrap, [encoded, None], iterations=100, rounds=10)
        original_length: int = len(original)

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: json like, json_content_type: disabled")
@pytest.mark.parametrize("json_parser", json_parser_params)
def test_json_collector_json_like_disabled(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture, json_parser: Callable[[bytes], Any]
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        original: bytes = (
            b"{" + MockContentBase.mock_content
        )  # we reduce json like (ie: {{"this": "seems", "a: "json"})
        encoded: str = base64.b64encode(original).decode("utf-8")
        last_length = benchmark.pedantic(wrap, [encoded, "disabled"], iterations=100, rounds=10)
        original_length: int = len(original)

        assert last_length == original_length


@pytest.mark.benchmark(group="real content: ndjson, json_content_type: None")
@pytest.mark.parametrize("json_parser,json_dumper", json_parser_and_dumper_params)
def test_json_collector_ndjson_none(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture,
    json_parser: Callable[[bytes], Any],
    json_dumper: Callable[[Any], bytes],
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        with mock.patch("share.expand_event_list_from_field.json_dumper", new=json_dumper):
            original: bytes = MockContentBase.mock_content  # we keep ndjson
            encoded: str = base64.b64encode(original).decode("utf-8")
            last_length = benchmark.pedantic(wrap, [encoded, None, True], iterations=100, rounds=10)
            original_length: int = len(original)
            if original.endswith(b"\n" * 2):
                original_length -= 2

            assert last_length == original_length


@pytest.mark.benchmark(group="real content: ndjson, json_content_type: ndjson")
@pytest.mark.parametrize("json_parser,json_dumper", json_parser_and_dumper_params)
def test_json_collector_ndjson_ndjson(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture,
    json_parser: Callable[[bytes], Any],
    json_dumper: Callable[[Any], bytes],
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        with mock.patch("share.expand_event_list_from_field.json_dumper", new=json_dumper):
            original: bytes = MockContentBase.mock_content  # we keep ndjson
            encoded: str = base64.b64encode(original).decode("utf-8")
            last_length = benchmark.pedantic(wrap, [encoded, "ndjson", True], iterations=100, rounds=10)
            original_length: int = len(original)
            if original.endswith(b"\n" * 2):
                original_length -= 2

            assert last_length == original_length


@pytest.mark.benchmark(group="real content: single json with expand_event_list_from_field, json_content_type: None")
@pytest.mark.parametrize("json_parser,json_dumper", json_parser_and_dumper_params)
def test_json_collector_expanded_none(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture,
    json_parser: Callable[[bytes], Any],
    json_dumper: Callable[[Any], bytes],
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        with mock.patch("share.expand_event_list_from_field.json_dumper", new=json_dumper):
            original: bytes = b'{"pleaseExpand": [' + MockContentBase.mock_content.replace(
                b"}\n{", b"}\n,\n{"
            ) + b"]}"  # we wrap a reduced to single ndjson in a field
            encoded: str = base64.b64encode(original).decode("utf-8")
            last_length = benchmark.pedantic(wrap, [encoded, None, True], iterations=100, rounds=10)
            original_length: int = len(original)
            if original.endswith(b"\n" * 2):
                original_length -= 2

            assert last_length == original_length


@pytest.mark.benchmark(group="real content: single json with expand_event_list_from_field, json_content_type: single")
@pytest.mark.parametrize("json_parser,json_dumper", json_parser_and_dumper_params)
def test_json_collector_expanded_single(
    benchmark: pytest_benchmark.fixture.BenchmarkFixture,
    json_parser: Callable[[bytes], Any],
    json_dumper: Callable[[Any], bytes],
) -> None:
    with mock.patch("storage.decorator.json_parser", new=json_parser):
        with mock.patch("share.expand_event_list_from_field.json_dumper", new=json_dumper):
            original: bytes = b'{"pleaseExpand": [' + MockContentBase.mock_content.replace(
                b"}\n{", b"}\n,\n{"
            ) + b"]}"  # we wrap a reduced to single ndjson in a field
            encoded: str = base64.b64encode(original).decode("utf-8")
            last_length = benchmark.pedantic(wrap, [encoded, "single", True], iterations=100, rounds=10)
            original_length: int = len(original)
            if original.endswith(b"\n" * 2):
                original_length -= 2

            assert last_length == original_length
