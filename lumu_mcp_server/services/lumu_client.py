"""Lumu Defender API client.

A thin async HTTP client over the Lumu Defender REST API. It owns a single
``httpx.AsyncClient`` for connection reuse; create one instance per process and
``aclose()`` it on shutdown (the server lifespan does this). Configuration
(api key, base URL, timeout) is injected — this module never reads the
environment.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

logger = logging.getLogger(__name__)

#: Adversary types accepted by the Lumu Defender API.
VALID_ADVERSARY_TYPES = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}

#: Incident statuses accepted by the Lumu Defender API.
VALID_STATUSES = {"open", "muted", "closed"}


class LumuDefenderClient:
    """Client for interacting with the Lumu Defender API."""

    #: Maximum date range allowed by the Lumu API, in days.
    MAX_DATE_RANGE_DAYS = 90

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://defender.lumu.io/api",
        timeout: float = 30.0,
    ) -> None:
        """Initialize the client.

        Args:
            api_key: Lumu Defender API key (the secret value, not a SecretStr).
            base_url: Base URL of the Lumu Defender REST API.
            timeout: Per-request timeout in seconds.
        """
        if not api_key:
            raise ValueError("Lumu Defender API key is required.")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # -- URL builders ----------------------------------------------------
    # The documented API groups incidents under /api/secops and administration
    # resources under /api/administration. base_url already ends in /api.

    def _incidents(self, path: str = "") -> str:
        """Build an incidents endpoint URL under /secops."""
        return f"{self.base_url}/secops/incidents{path}"

    def _administration(self, path: str) -> str:
        """Build an administration endpoint URL."""
        return f"{self.base_url}/administration{path}"

    # -- helpers ---------------------------------------------------------

    def _params(self, **extra: Any) -> dict[str, Any]:
        """Build query params, always including the API key."""
        return {"key": self.api_key, **extra}

    @staticmethod
    def _validate_adversary_types(adversary_types: list[str] | None) -> None:
        if adversary_types:
            invalid = set(adversary_types) - VALID_ADVERSARY_TYPES
            if invalid:
                raise ValueError(
                    f"Invalid adversary types: {invalid}. "
                    f"Must be one of {VALID_ADVERSARY_TYPES}"
                )

    def _validate_date_range(self, from_date: datetime, to_date: datetime) -> None:
        """Validate date range constraints.

        Raises:
            ValueError: If the date range is invalid.
        """
        if to_date < from_date:
            raise ValueError("to_date must be after from_date")

        # Allow a small buffer for timezone differences (1 day).
        max_future = datetime.now(UTC) + timedelta(days=1)
        if to_date > max_future:
            raise ValueError("to_date cannot be in the future")

        range_days = (to_date - from_date).days
        if range_days > self.MAX_DATE_RANGE_DAYS:
            raise ValueError(
                f"Date range of {range_days} days exceeds maximum of "
                f"{self.MAX_DATE_RANGE_DAYS} days. "
                f"Use fetch_all=True with automatic chunking for larger date ranges."
            )

    @staticmethod
    def _raise_for_status(exc: httpx.HTTPStatusError, *, incident_id: str | None = None) -> None:
        """Translate an httpx status error into a user-facing ValueError/Exception."""
        status = exc.response.status_code
        text = exc.response.text
        logger.error("API Error - Status: %s, Response: %s", status, text)
        if status == 401:
            raise ValueError(f"Invalid API key or unauthorized access. API Response: {text}")
        if status == 404 and incident_id is not None:
            raise ValueError(f"Incident {incident_id} not found. API Response (404): {text}")
        if status == 400:
            raise ValueError(f"Invalid request. API Response (400): {text}")
        raise Exception(f"API request failed with status {status}. Response: {text}")

    @staticmethod
    def _normalize_incidents(data: dict[str, Any], page: int, limit: int) -> dict[str, Any]:
        """Normalize the 'items' array to 'incidents' and attach pagination metadata."""
        if "items" in data and "incidents" not in data:
            data["incidents"] = data["items"]
        incidents_count = len(data.get("incidents", []))
        data["pagination"] = {
            "page": page,
            "limit": limit,
            "returned": incidents_count,
            "has_more": incidents_count >= limit,
        }
        return data

    async def _list_incidents_by_status(
        self,
        endpoint: str,
        status_label: str,
        adversary_types: list[str] | None,
        labels: list[int] | None,
        page: int,
        limit: int,
    ) -> dict[str, Any]:
        """Shared implementation for the open/muted/closed listing endpoints."""
        limit = max(1, min(limit, 100))
        self._validate_adversary_types(adversary_types)

        url = self._incidents(f"/{endpoint}")
        params = self._params(page=page + 1, items=limit)  # API is 1-indexed

        payload: dict[str, Any] = {}
        if adversary_types:
            payload["adversary-types"] = adversary_types
        if labels:
            payload["labels"] = labels

        logger.info("Fetching %s incidents (page=%s, items=%s)", status_label, page + 1, limit)

        try:
            response = await self._client.post(url, params=params, json=payload)
            response.raise_for_status()
            data = response.json()
            data = self._normalize_incidents(data, page, limit)
            logger.info(
                "Retrieved %s %s incidents (page=%s)",
                data["pagination"]["returned"], status_label, page + 1,
            )
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    # -- incidents listing ----------------------------------------------

    async def get_incidents(
        self,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        status: list[str] | None = None,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve incidents from Lumu Defender.

        Args:
            from_date: Search start date. Default is 7 days before now.
            to_date: Search end date. Default is now.
            status: Incident status filter ("open", "muted", "closed").
            adversary_types: Adversary types filter.
            labels: Label IDs filter.
            page: Page number for pagination (0-indexed). Default 0.
            limit: Items per page. Default 50, max 100.

        Returns:
            Dictionary containing the incidents data with pagination info.
        """
        if to_date is None:
            to_date = datetime.now(UTC)
        if from_date is None:
            from_date = to_date - timedelta(days=7)

        self._validate_date_range(from_date, to_date)
        limit = max(1, min(limit, 100))

        payload: dict[str, Any] = {
            "fromDate": from_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "toDate": to_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }

        if status:
            invalid = set(status) - VALID_STATUSES
            if invalid:
                raise ValueError(
                    f"Invalid status values: {invalid}. Must be one of {VALID_STATUSES}"
                )
            payload["status"] = status

        self._validate_adversary_types(adversary_types)
        if adversary_types:
            payload["adversary-types"] = adversary_types
        if labels:
            payload["labels"] = labels

        url = self._incidents("/all")
        params = self._params(page=page + 1, items=limit)  # API is 1-indexed

        logger.info(
            "Fetching incidents from %s to %s (page=%s, items=%s)",
            from_date, to_date, page + 1, limit,
        )

        try:
            response = await self._client.post(url, params=params, json=payload)
            response.raise_for_status()
            data = response.json()
            data = self._normalize_incidents(data, page, limit)
            logger.info("Retrieved %s incidents (page=%s, limit=%s)",
                        data["pagination"]["returned"], page, limit)
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    async def get_all_incidents(
        self,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        status: list[str] | None = None,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        max_pages: int = 100,
    ) -> dict[str, Any]:
        """Retrieve ALL incidents by automatically paginating through results."""
        all_incidents: list[dict[str, Any]] = []
        page = 0
        limit = 100  # Max per request for efficiency.

        logger.info("Fetching all incidents with auto-pagination...")

        while page < max_pages:
            result = await self.get_incidents(
                from_date=from_date,
                to_date=to_date,
                status=status,
                adversary_types=adversary_types,
                labels=labels,
                page=page,
                limit=limit,
            )
            incidents = result.get("incidents", [])
            all_incidents.extend(incidents)
            has_more = result.get("pagination", {}).get("has_more", False)
            logger.info("Page %s: retrieved %s incidents (total so far: %s)",
                        page, len(incidents), len(all_incidents))
            if not has_more or len(incidents) < limit:
                break
            page += 1

        logger.info("Completed fetching all incidents: %s total across %s pages",
                    len(all_incidents), page + 1)

        return {
            "incidents": all_incidents,
            "total": len(all_incidents),
            "pages_fetched": page + 1,
            "pagination": {"complete": page < max_pages, "total_items": len(all_incidents)},
        }

    async def get_all_incidents_chunked(
        self,
        from_date: datetime,
        to_date: datetime,
        status: list[str] | None = None,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        chunk_days: int = 30,
    ) -> dict[str, Any]:
        """Retrieve incidents across large date ranges by chunking into smaller queries."""
        all_incidents: list[dict[str, Any]] = []
        current_start = from_date
        chunks_processed = 0

        total_days = (to_date - from_date).days
        logger.info("Fetching incidents for %s days in %s-day chunks...", total_days, chunk_days)

        while current_start < to_date:
            current_end = min(current_start + timedelta(days=chunk_days), to_date)
            logger.info("Processing chunk %s: %s to %s",
                        chunks_processed + 1, current_start.date(), current_end.date())
            result = await self.get_all_incidents(
                from_date=current_start,
                to_date=current_end,
                status=status,
                adversary_types=adversary_types,
                labels=labels,
            )
            chunk_incidents = result.get("incidents", [])
            all_incidents.extend(chunk_incidents)
            chunks_processed += 1
            logger.info("Chunk %s: retrieved %s incidents", chunks_processed, len(chunk_incidents))
            current_start = current_end

        # Deduplicate by ID in case of overlap at chunk boundaries.
        seen_ids: set[Any] = set()
        unique_incidents: list[dict[str, Any]] = []
        duplicates_removed = 0
        for incident in all_incidents:
            incident_id = incident.get("id")
            if incident_id and incident_id not in seen_ids:
                seen_ids.add(incident_id)
                unique_incidents.append(incident)
            else:
                duplicates_removed += 1

        logger.info(
            "Completed chunked fetch: %s unique incidents (%s duplicates removed) across %s chunks",
            len(unique_incidents), duplicates_removed, chunks_processed,
        )

        return {
            "incidents": unique_incidents,
            "total": len(unique_incidents),
            "chunks_processed": chunks_processed,
            "duplicates_removed": duplicates_removed,
            "date_range": {
                "from": from_date.isoformat(),
                "to": to_date.isoformat(),
                "days": total_days,
            },
        }

    async def get_open_incidents(
        self,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve open incidents from Lumu Defender."""
        return await self._list_incidents_by_status(
            "open", "open", adversary_types, labels, page, limit
        )

    async def get_muted_incidents(
        self,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve muted incidents from Lumu Defender."""
        return await self._list_incidents_by_status(
            "muted", "muted", adversary_types, labels, page, limit
        )

    async def get_closed_incidents(
        self,
        adversary_types: list[str] | None = None,
        labels: list[int] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve closed incidents from Lumu Defender."""
        return await self._list_incidents_by_status(
            "closed", "closed", adversary_types, labels, page, limit
        )

    # -- single incident -------------------------------------------------

    async def get_incident_details(self, incident_id: str) -> dict[str, Any]:
        """Retrieve details of a specific incident."""
        url = self._incidents(f"/{incident_id}/details")
        logger.info("Fetching details for incident %s", incident_id)
        try:
            response = await self._client.get(url, params=self._params())
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved details for incident %s", incident_id)
            return {"incident": data}  # Wrap for consistency.
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e, incident_id=incident_id)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    async def get_incident_events_groupings(
        self,
        incident_id: str,
        status: list[str] | None = None,
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve the event groupings of a specific incident.

        Args:
            incident_id: The UUID of the incident.
            status: Optional status filter (open, muted, closed).
            page: Page number for pagination (0-indexed). Default 0.
            limit: Items per page. Default 50, max 100.
        """
        limit = max(1, min(limit, 100))
        url = self._incidents(f"/{incident_id}/events-groupings")
        params = self._params(page=page + 1, items=limit)  # API is 1-indexed
        payload: dict[str, Any] = {
            "status": status or ["open", "closed", "muted"],
            "sort-criteria": [],
            "filters": [],
        }
        logger.info("Fetching event groupings for incident %s (page=%s)", incident_id, page + 1)
        try:
            response = await self._client.post(url, params=params, json=payload)
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved event groupings for incident %s", incident_id)
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e, incident_id=incident_id)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    async def get_security_event_details(
        self,
        incident_id: str,
        event_id: str,
        sort: str = "asc",
        page: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve the raw data of a specific event group within an incident.

        Args:
            incident_id: The UUID of the incident.
            event_id: The event-grouping ID (from get_incident_events_groupings).
            sort: Sort order for the raw events ("asc" or "desc").
            page: Page number for pagination (0-indexed). Default 0.
            limit: Items per page. Default 50, max 100.
        """
        limit = max(1, min(limit, 100))
        url = self._incidents(f"/{incident_id}/security-events/{event_id}/details")
        params = self._params(page=page + 1, items=limit)  # API is 1-indexed
        payload: dict[str, Any] = {"sort": sort, "hints": []}
        logger.info(
            "Fetching security-event details for incident %s event %s (page=%s)",
            incident_id, event_id, page + 1,
        )
        try:
            response = await self._client.post(url, params=params, json=payload)
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved security-event details for incident %s event %s",
                        incident_id, event_id)
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e, incident_id=incident_id)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    # -- incident actions ------------------------------------------------

    async def _post_incident_action(
        self, incident_id: str, action: str, payload: dict[str, Any], success_message: str
    ) -> dict[str, Any]:
        """Shared implementation for POST actions on a single incident."""
        url = self._incidents(f"/{incident_id}/{action}")
        logger.info("Performing '%s' on incident %s", action, incident_id)
        try:
            response = await self._client.post(url, params=self._params(), json=payload)
            response.raise_for_status()
            data = (
                response.json()
                if response.content
                else {"success": True, "message": success_message}
            )
            logger.info("Incident %s: '%s' succeeded", incident_id, action)
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e, incident_id=incident_id)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    async def mark_incident_as_read(self, incident_id: str) -> dict[str, Any]:
        """Mark an incident as read."""
        return await self._post_incident_action(
            incident_id, "mark-as-read", {}, "Incident marked as read successfully"
        )

    async def mute_incident(self, incident_id: str, comment: str = "") -> dict[str, Any]:
        """Mute an incident."""
        return await self._post_incident_action(
            incident_id, "mute", {"comment": comment}, "Incident muted successfully"
        )

    async def unmute_incident(self, incident_id: str, comment: str = "") -> dict[str, Any]:
        """Unmute an incident."""
        return await self._post_incident_action(
            incident_id, "unmute", {"comment": comment}, "Incident unmuted successfully"
        )

    async def close_incident(self, incident_id: str, comment: str = "") -> dict[str, Any]:
        """Close an incident."""
        return await self._post_incident_action(
            incident_id, "close", {"comment": comment}, "Incident closed successfully"
        )

    async def comment_incident(self, incident_id: str, comment: str) -> dict[str, Any]:
        """Add a comment to a specific incident."""
        return await self._post_incident_action(
            incident_id, "comment", {"comment": comment}, "Comment added successfully"
        )

    async def begin_incident_work(
        self, incident_id: str, assignee: int, comment: str = ""
    ) -> dict[str, Any]:
        """Begin work on an incident and assign it to a user.

        Args:
            incident_id: The UUID of the incident.
            assignee: The user ID to assign the incident to.
            comment: Optional comment.
        """
        return await self._post_incident_action(
            incident_id,
            "begin-work",
            {"comment": comment, "data": {"assignee": assignee}},
            "Work begun on incident successfully",
        )

    async def get_incident_updates(
        self, offset: int = 0, items: int = 50, time: int = 5
    ) -> dict[str, Any]:
        """Get real-time updates on incident operations (long-poll).

        Args:
            offset: Starting offset for pagination.
            items: Number of items to return.
            time: Maximum number of seconds the server waits for updates.
        """
        url = self._incidents("/updates")
        params = self._params(offset=offset, items=items, time=time)
        logger.info("Fetching incident updates (offset=%s, items=%s, time=%s)", offset, items, time)
        try:
            response = await self._client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved %s incident updates", len(data.get("updates", [])))
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    # -- administration --------------------------------------------------

    async def get_labels(self, page: int = 0, limit: int = 50) -> dict[str, Any]:
        """Retrieve all labels.

        Args:
            page: Page number for pagination (0-indexed). Default 0.
            limit: Items per page. Default 50, max 100.
        """
        limit = max(1, min(limit, 100))
        url = self._administration("/labels")
        params = self._params(page=page + 1, items=limit)  # API is 1-indexed
        logger.info("Fetching labels (page=%s, items=%s)", page + 1, limit)
        try:
            response = await self._client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved %s labels", len(data.get("labels", [])))
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")

    async def get_label(self, label_id: int) -> dict[str, Any]:
        """Retrieve a specific label by ID.

        Args:
            label_id: The numeric ID of the label.
        """
        url = self._administration(f"/labels/{label_id}")
        logger.info("Fetching label %s", label_id)
        try:
            response = await self._client.get(url, params=self._params())
            response.raise_for_status()
            data = response.json()
            logger.info("Retrieved label %s", label_id)
            return data
        except httpx.HTTPStatusError as e:
            self._raise_for_status(e)
        except httpx.RequestError as e:
            raise Exception(f"Network error while connecting to Lumu API: {e!s}")
