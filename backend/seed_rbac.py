from __future__ import annotations

from app import create_app
from services.rbac_service import seed_rbac_data


def main() -> int:
    app = create_app()
    with app.app_context():
        seed_rbac_data()
    print("RBAC data seeded successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

