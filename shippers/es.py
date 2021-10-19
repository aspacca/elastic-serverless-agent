# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

import hashlib
from typing import Any

import elasticapm  # noqa: F401
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk as es_bulk

from .shipper import CommonShipper


class ElasticsearchShipper(CommonShipper):
    _bulk_actions: list[dict[str, Any]] = []
    _bulk_batch_size: int = 10000

    def __init__(self, hosts: list[str], username: str, password: str, scheme: str, dataset: str, namespace: str):

        self._es_client = Elasticsearch(
            hosts,
            http_auth=(username, password),
            scheme=scheme,
        )

        self._dataset = dataset
        self._namespace = namespace

        self._es_index = f"logs-{dataset}-{namespace}"

    @staticmethod
    def _s3_object_id(event_payload: dict[str, Any]) -> str:
		"""
		Port of
		https://github.com/elastic/beats/blob/21dca31b6296736fa90fae39bff71f063522420f/x-pack/filebeat/input/awss3/s3_objects.go#L364-L371
		https://github.com/elastic/beats/blob/21dca31b6296736fa90fae39bff71f063522420f/x-pack/filebeat/input/awss3/s3_objects.go#L356-L358
		"""
        offset: int = event_payload["fields"]["log"]["offset"]
        bucket_arn: str = event_payload["fields"]["aws"]["s3"]["bucket"]["arn"]
        object_key: str = event_payload["fields"]["aws"]["s3"]["object"]["key"]

        src: str = f"{bucket_arn}{object_key}"
        hex_prefix = hashlib.sha256(src.encode("UTF-8")).hexdigest()[:10]

        return f"{hex_prefix}-{offset:012d}"

    def _enrich_event(self, event_payload: dict[str, Any]) -> None:
        event_payload["data_stream"] = {
            "type": "logs",
            "dataset": self._dataset,
            "namespace": self._namespace,
        }

        event_payload["event"] = {"dataset": self._dataset, "original": event_payload["fields"]["message"]}

        event_payload["tags"] = ["preserve_original_event", "forwarded", self._dataset.replace(".", "-")]

    def send(self, event: dict[str, Any]) -> Any:
        self._enrich_event(event_payload=event)

        event["_op_type"] = "create"
        event["_index"] = self._es_index
        event["_id"] = self._s3_object_id(event)
        self._bulk_actions.append(event)

        if len(self._bulk_actions) < self._bulk_batch_size:
            return

        es_bulk(self._es_client, self._bulk_actions)
        self._bulk_actions = []

    def flush(self) -> None:
        if len(self._bulk_actions) > 1:
            es_bulk(self._es_client, self._bulk_actions)

        self._bulk_actions = []
