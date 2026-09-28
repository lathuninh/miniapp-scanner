from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file: str
    line: int
    code: str
    description: str
    suggestion: str
    engine: str = "regex"
    trace: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)