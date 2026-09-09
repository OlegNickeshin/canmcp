from dataclasses import asdict, dataclass, field
from enum import StrEnum

from canmcp import __version__


class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Check:
    id: str
    status: Status
    message: str
    source: str | None = None


def worst(checks: list[Check]) -> Status:
    return max((c.status for c in checks), key=list(Status).index, default=Status.WARN)


@dataclass
class Profile:
    status: Status
    reasons: list[Check]


@dataclass
class Generic:
    status: Status
    checks: list[Check]


@dataclass
class Report:
    url: str
    generic: Generic
    clients: dict[str, Profile]
    protocol_version: str | None = None
    advertised_versions: list[str] = field(default_factory=list)
    final_url: str | None = None
    schema_version: str = "1"
    scanner_version: str = __version__
    limitations: list[str] = field(
        default_factory=lambda: [
            "A bounded local observation, not protocol certification or a cloud-client test.",
            "No tools/call or remote schema retrieval. OAuth runs only when explicitly requested.",
            "Cloud routing, account policies, and tool behavior are not verified.",
        ]
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Evidence:
    url: str
    final_url: str = ""
    checks: list[Check] = field(default_factory=list)
    protocol_version: str | None = None
    advertised_versions: list[str] = field(default_factory=list)
    protocol_ok: bool = False
    protected: bool = False
    missing_descriptions: int = 0
    missing_annotations: int = 0
    missing_claude_hints: int = 0
    tool_count: int = 0
    auth_servers: list[dict] = field(default_factory=list)
    resource: str | None = None
    oauth_scopes: list[str] = field(default_factory=list)

    def add(self, id: str, status: Status, message: str, source: str | None = None) -> None:
        self.checks.append(Check(id, status, message, source))
