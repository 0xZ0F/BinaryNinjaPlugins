from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class BaseEdge:
    class_name: str
    class_offset: int
    vft_addr: Optional[int]


@dataclass
class ClassNode:
    class_name: str
    rtti_obj_addr: int
    vft_addr: Optional[int]
    bases: List[BaseEdge] = field(default_factory=list)


@dataclass
class ClassGraph:
    by_name: Dict[str, ClassNode] = field(default_factory=dict)
    by_vft: Dict[int, ClassNode] = field(default_factory=dict)

    def add(self, node: ClassNode) -> None:
        self.by_name[node.class_name] = node
        if node.vft_addr is not None:
            self.by_vft[node.vft_addr] = node

    def class_for_vft(self, vft_addr: int) -> Optional[ClassNode]:
        return self.by_vft.get(vft_addr)

    def __len__(self) -> int:
        return len(self.by_name)
