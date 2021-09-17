import datetime
import json
from typing import Any, Generator

import elasticapm
from event import _default_event
from utils import get_bucket_name_from_arn

from share import Config, logger
from storage import CommonStorage, StorageFactory


def _handle_sqs_event(config: Config, event) -> Generator[tuple[dict[str, Any], int, int, int, int], None, None]:
    for sqs_record_n, sqs_record in enumerate(event["Records"]):
        event_input = config.get_input_by_type_and_id("sqs", sqs_record["eventSourceARN"])
        if not event_input:
            return None

        body = json.loads(sqs_record["body"])
        for s3_record_n, s3_record in enumerate(body["Records"]):
            aws_region = s3_record["awsRegion"]
            bucket_arn = s3_record["s3"]["bucket"]["arn"]
            object_key = s3_record["s3"]["object"]["key"]
            last_ending_offset = s3_record["last_ending_offset"] if "last_ending_offset" in s3_record else 0
            last_beginning_offset = s3_record["last_beginning_offset"] if "last_beginning_offset" in s3_record else 0

            if len(bucket_arn) == 0 or len(object_key) == 0:
                raise Exception("Cannot find bucket_arn or object_key for s3")

            bucket_name: str = get_bucket_name_from_arn(bucket_arn)
            storage: CommonStorage = StorageFactory.create(
                storage_type="s3", bucket_name=bucket_name, object_key=object_key
            )

            span = elasticapm.capture_span(f"WAIT FOR OFFSET STARTING AT {last_ending_offset}")
            span.__enter__()
            for log_event, beginning_offset, ending_offset in storage.get_by_lines(
                range_start=last_ending_offset, last_beginning_offset=last_beginning_offset
            ):
                # let's be sure that on the first yield `ending_offset`
                # doesn't overlap `last_ending_offset`: in case we
                # skip in order to not ingest twice the same event
                if ending_offset < last_ending_offset:
                    logger.debug(
                        "skipping event",
                        extra={
                            "ending_offset": ending_offset,
                            "last_ending_offset": last_ending_offset,
                        },
                    )
                    continue

                if span:
                    span.__exit__(None, None, None)
                    span = None

                es_event = _default_event.copy()
                es_event["@timestamp"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                es_event["fields"]["message"] = log_event.decode("UTF-8")
                es_event["fields"]["log"]["offset"] = beginning_offset

                es_event["fields"]["log"]["file"]["path"] = "https://{0}.s3.{1}.amazonaws.com/{1}".format(
                    bucket_name, object_key
                )

                es_event["fields"]["aws"]["s3"] = {
                    "bucket": {"name": bucket_name, "arn": bucket_arn},
                    "object": {"key": object_key},
                }

                es_event["fields"]["cloud"]["region"] = aws_region

                yield es_event, beginning_offset, ending_offset, sqs_record_n, s3_record_n
