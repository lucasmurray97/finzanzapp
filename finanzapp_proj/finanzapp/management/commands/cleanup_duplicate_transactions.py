from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from django.core.management.base import BaseCommand
from django.db import transaction

from finanzapp.models import Transaction


class Command(BaseCommand):
    help = "Remove duplicate transactions, keeping the latest (highest id) in each group."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Actually delete duplicates (default is dry-run).",
        )
        parser.add_argument(
            "--round-amount",
            type=int,
            default=2,
            help="Round amount to N decimals when grouping (default: 2).",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        round_places = options["round_amount"]

        total_groups = 0
        total_deleted = 0

        buckets = {}
        for txn in Transaction.objects.all().order_by("id"):
            description_norm = " ".join((txn.description or "").split()).strip().lower()
            amount = txn.amount
            if round_places is not None:
                try:
                    amount = (
                        Decimal(str(amount))
                        .quantize(Decimal("1").scaleb(-round_places), rounding=ROUND_HALF_UP)
                    )
                except (InvalidOperation, ValueError):
                    amount = Decimal("0")
            key = (txn.user_id, txn.date, amount, description_norm)
            buckets.setdefault(key, []).append(txn)

        for (user_id, date, amount, description_norm), items in buckets.items():
            if len(items) < 2:
                continue
            total_groups += 1
            keep = items[-1]
            delete_ids = [item.id for item in items[:-1]]
            total_deleted += len(delete_ids)
            self.stdout.write(
                f"User={user_id} amount={amount} date={date} "
                f"desc={description_norm!r} keep_id={keep.id} delete={len(delete_ids)}"
            )
            if apply_changes:
                with transaction.atomic():
                    Transaction.objects.filter(id__in=delete_ids).delete()

        action = "Deleted" if apply_changes else "Would delete"
        self.stdout.write(f"{action} {total_deleted} transactions across {total_groups} groups.")
