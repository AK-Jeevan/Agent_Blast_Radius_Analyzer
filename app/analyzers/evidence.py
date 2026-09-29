"""Evidence ledger: every conclusion must point at evidence, and evidence is de-duplicated.

Rules enforced here (docs/ANALYSIS_ENGINE_SPEC.md §5):

* a FACT must cite a concrete source that exists in the parsed input;
* an INFERENCE needs at least two supporting FACTs, otherwise the ledger downgrades it;
* untrusted sources can never produce a FACT;
* identical statements collapse to one id, so evidence counts mean something.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.analysis import EvidenceItem
from app.schemas.common import EvidenceKind, Source, SourceKind
from app.utils.ids import numbered_id


@dataclass
class EvidenceLedger:
    """Content-addressed evidence store. Ids are assigned in insertion order for readability."""

    _items: dict[str, EvidenceItem] = field(default_factory=dict)
    _by_key: dict[tuple[object, ...], str] = field(default_factory=dict)

    def add(
        self,
        kind: EvidenceKind,
        subject: str,
        predicate: str,
        *,
        obj: str | None = None,
        polarity: bool = True,
        value: object | None = None,
        source: Source | None = None,
        supports: tuple[str, ...] = (),
        note: str | None = None,
    ) -> str:
        """Record a statement and return its stable id (deduplicated by content)."""
        src = source or Source(kind=SourceKind.DERIVED, ref="analysis", trusted=True)
        candidate = EvidenceItem(
            id="pending",
            kind=kind,
            subject=subject,
            predicate=predicate,
            object=obj,
            polarity=polarity,
            value=value,
            source=src,
            supports=supports,
            note=note,
        )
        if candidate.dedup_key in self._by_key:
            return self._by_key[candidate.dedup_key]
        evidence_id = numbered_id("evidence", len(self._items) + 1)
        item = candidate.model_copy(update={"id": evidence_id})
        self._items[evidence_id] = item
        self._by_key[item.dedup_key] = evidence_id
        return evidence_id

    def fact(
        self,
        subject: str,
        predicate: str,
        *,
        obj: str | None = None,
        value: object | None = None,
        source: Source | None = None,
        note: str | None = None,
        polarity: bool = True,
    ) -> str:
        """Record a FACT -- but only when the source is trusted.

        Untrusted text is recorded as an INFERENCE instead: the analyzed environment cannot assert
        facts about itself to us.
        """
        if source is not None and source.untrusted:
            return self.add(
                EvidenceKind.INFERENCE,
                subject,
                predicate,
                obj=obj,
                polarity=polarity,
                value=value,
                source=source,
                note=((note + " ") if note else "") + "[untrusted_derived]",
            )
        return self.add(
            EvidenceKind.FACT,
            subject,
            predicate,
            obj=obj,
            polarity=polarity,
            value=value,
            source=source,
            note=note,
        )

    def inference(
        self,
        subject: str,
        predicate: str,
        *,
        obj: str | None = None,
        supports: tuple[str, ...] = (),
        value: object | None = None,
        note: str | None = None,
        polarity: bool = True,
        source: Source | None = None,
    ) -> str:
        """Record an INFERENCE. Fewer than two supporting facts degrades it to a HYPOTHESIS."""
        fact_supports = tuple(
            evidence_id
            for evidence_id in supports
            if evidence_id in self._items and self._items[evidence_id].kind == EvidenceKind.FACT
        )
        kind = EvidenceKind.INFERENCE if len(fact_supports) >= 2 else EvidenceKind.HYPOTHESIS
        return self.add(
            kind,
            subject,
            predicate,
            obj=obj,
            polarity=polarity,
            value=value,
            source=source,
            supports=supports,
            note=note,
        )

    def hypothesis(
        self,
        subject: str,
        predicate: str,
        *,
        obj: str | None = None,
        supports: tuple[str, ...] = (),
        note: str | None = None,
    ) -> str:
        return self.add(
            EvidenceKind.HYPOTHESIS, subject, predicate, obj=obj, supports=supports, note=note
        )

    def contradiction(
        self,
        subject: str,
        predicate: str,
        *,
        obj: str | None = None,
        supports: tuple[str, ...] = (),
        note: str | None = None,
    ) -> str:
        return self.add(
            EvidenceKind.CONTRADICTION,
            subject,
            predicate,
            obj=obj,
            polarity=False,
            supports=supports,
            note=note,
        )

    # --- queries ------------------------------------------------------------------------
    def get(self, evidence_id: str) -> EvidenceItem | None:
        return self._items.get(evidence_id)

    def items(self) -> list[EvidenceItem]:
        return [self._items[key] for key in sorted(self._items)]

    def require(self, evidence_ids: list[str]) -> list[EvidenceItem]:
        """Resolve ids to items, raising when a claim cites evidence that does not exist."""
        missing = [evidence_id for evidence_id in evidence_ids if evidence_id not in self._items]
        if missing:
            raise KeyError(f"claim cites non-existent evidence: {missing}")
        return [self._items[evidence_id] for evidence_id in evidence_ids]

    def count_kinds(self, evidence_ids: list[str]) -> dict[str, int]:
        counts = {kind.value: 0 for kind in EvidenceKind}
        for evidence_id in evidence_ids:
            item = self._items.get(evidence_id)
            if item is not None:
                counts[item.kind.value] += 1
        return counts

    def fact_count(self, evidence_ids: list[str]) -> int:
        return self.count_kinds(evidence_ids)[EvidenceKind.FACT.value]

    def dangling(self, evidence_ids: list[str]) -> list[str]:
        return [evidence_id for evidence_id in evidence_ids if evidence_id not in self._items]

    def find_by_subject(self, subject: str) -> list[EvidenceItem]:
        return [item for item in self.items() if item.subject == subject]

    def render_all(self) -> list[str]:
        return [item.render() for item in self.items()]

    def __len__(self) -> int:
        return len(self._items)

    @classmethod
    def from_items(cls, items: list[EvidenceItem]) -> EvidenceLedger:
        """Rebuild a ledger from a previously reported evidence list.

        The agentic verifier extends the *same* evidence space as the deterministic run, so a claim
        cites the very facts the baseline recorded rather than a parallel, unverifiable set.
        """
        ledger = cls()
        for item in items:
            if item.id in ledger._items:
                continue
            ledger._items[item.id] = item
            ledger._by_key[item.dedup_key] = item.id
        return ledger
