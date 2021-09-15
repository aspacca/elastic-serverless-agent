from typing import Generator

import boto3
import elasticapm  # noqa: F401
from botocore.response import StreamingBody

from share import by_line, deflate, get_logger

from .storage import CommonStorage

logger = get_logger("storage.s3")


class S3Storage(CommonStorage):
    _chunk_size: int = 1024 * 1024

    def __init__(self, bucket_name: str, object_key: str):
        self._bucket_name: str = bucket_name
        self._object_key: str = object_key

        # Get the service resource
        self._s3_client = boto3.client("s3")

    @by_line
    @deflate
    def _generate(self, body: StreamingBody, content_type: str) -> Generator[tuple[bytes, int], None, None]:
        for chunk in iter(lambda: body.read(self._chunk_size), b""):
            logger.debug("_generate", extra={"offset": len(chunk)})
            yield chunk, len(chunk)

    def get_by_lines(self) -> Generator[tuple[bytes, int], None, None]:
        logger.debug("get_by_lines", extra={"bucket_name": self._bucket_name, "object_key": self._object_key})
        s3_object = self._s3_client.get_object(
            Bucket=self._bucket_name,
            Key=self._object_key,
        )

        return self._generate(s3_object["Body"], s3_object["ContentType"])

    def get_as_string(self) -> str:
        logger.debug("get_as_string", extra={"bucket_name": self._bucket_name, "object_key": self._object_key})
        s3_object = self._s3_client.get_object(
            Bucket=self._bucket_name,
            Key=self._object_key,
        )

        body: StreamingBody = s3_object["Body"]
        return body.read(s3_object["ContentLength"]).decode("UTF-8")
