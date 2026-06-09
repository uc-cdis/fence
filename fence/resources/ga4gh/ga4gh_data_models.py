from collections import defaultdict
from typing import Optional
from pydantic import BaseModel


class BulkObjectAccessIds(BaseModel):
    bulk_object_id: str
    bulk_access_ids: list[str]


class BulkObjectAccessRequest(BaseModel):
    passports: Optional[list[str]] = None
    bulk_object_access_ids: list[BulkObjectAccessIds]

    def map_access_to_object_ids(self):
        result = defaultdict(list)
        for item in self.bulk_object_access_ids:
            for access_id in item.bulk_access_ids:
                result[access_id].append(item.bulk_object_id)

        return result


class ResolvedDrsObject(BaseModel):
    drs_object_id: str
    drs_access_id: str
    url: str
    headers: Optional[str]


class UnresolvedDrsObject(BaseModel):
    error_code: int
    object_ids: list[str]


class BulkObjectSummary(BaseModel):
    requested: int
    resolved: int
    unresolved: int


class BulkObjectAccessResponse(BaseModel):
    summary: BulkObjectSummary
    unresolved_drs_objects: UnresolvedDrsObject
    resolved_drs_object_access_urls: ResolvedDrsObject
