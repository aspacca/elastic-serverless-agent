# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

from __future__ import annotations

from typing import Any, Callable, Optional

import hyperscan

MatchEventHandlerCallable = Callable[[int, int, int, int, Optional[Any]], Optional[bool]]


class IncludeExcludeRule:
    """
    IncludeExcludeRule represents a pattern rule
    """

    def __init__(self, patterns: list[str]):
        self.patterns = patterns
        hyperscan_patterns = (
            # expression, id, flags
            (pattern.encode("utf-8"), pattern_n + 1, hyperscan.HS_FLAG_DOTALL)
            for pattern_n, pattern in enumerate(self.patterns)
        )
        expressions, ids, flags = zip(*hyperscan_patterns)

        self.hyperscan_db = hyperscan.Database()
        self.hyperscan_db.compile(expressions=expressions, ids=ids, elements=len(self.patterns), flags=flags)

    def scan(self, line: bytes, match_event_handler: MatchEventHandlerCallable) -> None:
        self.hyperscan_db.scan(line, match_event_handler=match_event_handler)

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, IncludeExcludeRule)

        return self.patterns == other.patterns


class IncludeExcludeFilter:
    """
    Base class for IncludeExclude filter
    """

    def __init__(
        self,
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ):
        self._include_rules: Optional[IncludeExcludeRule] = None
        self._exclude_rules: Optional[IncludeExcludeRule] = None

        if include_patterns is not None and len(include_patterns) > 0:
            self.include_rules = IncludeExcludeRule(patterns=include_patterns)

        if exclude_patterns is not None and len(exclude_patterns) > 0:
            self.exclude_rules = IncludeExcludeRule(patterns=exclude_patterns)

        self._always_yield = self._include_rules is None and self._exclude_rules is None

        self._include_only = self._include_rules is not None and self._exclude_rules is None
        self._exclude_only = self._exclude_rules is not None and self._include_rules is None

        self._is_included_matched = False
        self._is_excluded_matched = False

    def _is_included(self, message: str) -> bool:
        assert self._include_rules is not None

        self._is_included_matched = False

        def on_match(match_id: int, from_: int, to: int, flags: int, context: Optional[Any] = None) -> Optional[bool]:
            if match_id > 0:
                self._is_included_matched = True
                return True

            return None

        try:
            self._include_rules.scan(message.encode("utf-8"), match_event_handler=on_match)
        except hyperscan.error:
            return True

        if self._is_included_matched:
            return True

        return False

    def _is_excluded(self, message: str) -> bool:
        assert self._exclude_rules is not None

        self._is_excluded_matched = False

        def on_match(match_id: int, from_: int, to: int, flags: int, context: Optional[Any] = None) -> Optional[bool]:
            if match_id > 0:
                self._is_excluded_matched = True
                return True

            return None

        try:
            self._exclude_rules.scan(message.encode("utf-8"), match_event_handler=on_match)
        except hyperscan.error:
            return True

        if self._is_excluded_matched:
            return True

        return False

    def filter(self, message: str) -> bool:
        """
        filter returns True if the event is included or not excluded
        """

        if self._always_yield:
            return True

        if self._include_only:
            return self._is_included(message)

        if self._exclude_only:
            return not self._is_excluded(message)

        if self._is_excluded(message):
            return False

        return self._is_included(message)

    def __eq__(self, other: object) -> bool:
        assert isinstance(other, IncludeExcludeFilter)

        return self.include_rules == other.include_rules and self.exclude_rules == other.exclude_rules

    @property
    def include_rules(self) -> Optional[IncludeExcludeRule]:
        return self._include_rules

    @include_rules.setter
    def include_rules(self, value: IncludeExcludeRule) -> None:
        self._include_rules = value

    @property
    def exclude_rules(self) -> Optional[IncludeExcludeRule]:
        return self._exclude_rules

    @exclude_rules.setter
    def exclude_rules(self, value: IncludeExcludeRule) -> None:
        self._exclude_rules = value
