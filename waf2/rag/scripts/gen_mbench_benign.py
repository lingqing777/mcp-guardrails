"""M-Bench-Core: schema-driven benign sample generator (template source).

Generates the ~700 "template" benign records that cover the stable
business-baseline of each real MCP tool. These records are NOT paired with
attacks — they are bulk-generated business-normal calls whose role is to
provide a stable FPR denominator.

The 300 "handcrafted" hard-negatives are NOT generated here. They are
hand-written and paired_with the corresponding attack via `paired_with`.

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.gen_mbench_benign \\
        --out waf2/rag/eval/m-bench-core/benign.jsonl \\
        --count 700 \\
        [--seed 42] [--start-index 0]

Idempotency: with a fixed --seed and --start-index the output is reproducible.
The generator appends `mbc:benign:NNNN` IDs starting at --start-index.

See waf2/rag/eval/m-bench-core/README.md for the tool universe and field
semantics.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

# ---------- fixture pools (business-normal values per tool) ----------

CUSTOMER_NAMES = [
    "Acme Drop Shipping LLC", "Sunshine Bakery Co", "Wong Hardware Pty",
    "Global Fashion Outlet", "Tech Forward Inc", "Mountain View Coffee Roasters",
    "Riverside Auto Parts", "Sunset Books & Stationery", "Helios Solar Solutions",
    "Northwind Traders", "Contoso Office Supplies", "Fabrikam Catering",
    "Aperture Science Lab Inc", "Black Mesa Research", "Wayne Enterprises",
    "Stark Industries", "Tyrell Corporation Limited", "Cyberdyne Systems",
    "Initech Software Solutions", "Vandelay Industries", "Soylent Corp",
    "Hooli Cloud Services", "Pied Piper Inc", "Dunder Mifflin Paper",
    "Beach Babes Surf Shop", "Pony Express Logistics", "Ace Tire & Wheel",
    "Bluefin Sushi & Bento", "Cozy Corner Café", "Dapper Gent Apparel",
]

PRODUCT_NAMES = [
    "Stainless Steel Water Bottle 1L", "Eco-friendly Yoga Mat", "Organic Coffee Beans 500g",
    "Bamboo Cutting Board Set", "Wireless Bluetooth Earbuds", "USB-C Charging Cable 2m",
    "Cast Iron Skillet 10in", "LED Desk Lamp with Wireless Charger", "Memory Foam Pillow",
    "Recycled Notebook A5", "Glass Storage Container 4-Pack", "Compostable Phone Case",
    "Insulated Lunch Bag", "Smart Fitness Tracker", "Adjustable Standing Desk",
    "Linen Throw Blanket", "Ceramic Tea Set", "Espresso Machine Pro 2024",
    "Mechanical Keyboard RGB", "Ergonomic Mouse Wireless", "4K Webcam with Microphone",
    "Air Purifier HEPA", "Robot Vacuum Mini", "Smart Plug 4-Pack",
    "Wool Beanie Adult", "Leather Wallet RFID", "Backpack Daypack 25L",
    "Running Shoes Trail", "Yoga Block Cork", "Resistance Band Set",
]

PRODUCT_DESCRIPTIONS = [
    "High-quality {x}, eco-friendly and durable. Perfect for daily use.",
    "Our best-selling {x}. Designed for comfort and longevity.",
    "Premium grade {x}. Made with sustainable materials.",
    "The classic {x} — built to last, easy to clean.",
    "Bestseller for 3 years running. {x} loved by customers worldwide.",
    "Limited edition {x}. Crafted with attention to every detail.",
    "Customer-favorite {x}. Featured in Wired magazine.",
    "Versatile and reliable {x}. Backed by our 2-year warranty.",
]

LEGAL_FILE_PATHS = [
    "docs/setup.md", "docs/api-reference.md", "docs/user-guide.pdf",
    "data/reports/2026-Q1-sales.csv", "data/reports/2026-Q2-revenue.csv",
    "config/app.toml", "templates/email/welcome.html", "templates/invoice.pdf",
    "logs/app/2026-05-01.log", "logs/app/2026-05-02.log",
    "uploads/images/product-1234.jpg", "uploads/images/banner-5678.png",
    "static/css/main.css", "static/js/app.bundle.js",
    "README.md", "CHANGELOG.md", "LICENSE",
    "tests/fixtures/sample-order.json", "tests/fixtures/sample-user.json",
    "scripts/migrate.py", "scripts/seed-data.py",
    "build/dist/index.html", "build/dist/assets/logo.svg",
    "src/main/java/com/example/App.java", "src/main/resources/application.yml",
]

LEGAL_URLS_HTTP_CLIENT = [
    ("https://api.example.com/v1/products", "GET"),
    ("https://api.example.com/v1/orders/12345", "GET"),
    ("https://api.example.com/v2/customers/search?q=acme", "GET"),
    ("https://api.weather.com/forecast?city=Seattle", "GET"),
    ("https://api.exchangerate.host/latest?base=USD", "GET"),
    ("https://api.stripe.com/v1/charges", "POST"),
    ("https://api.sendgrid.com/v3/mail/send", "POST"),
    ("https://api.github.com/repos/example/repo/issues", "GET"),
    ("https://api.openweathermap.org/data/2.5/weather", "GET"),
    ("https://www.googleapis.com/calendar/v3/users/me/events", "GET"),
    ("https://api.twilio.com/2010-04-01/Accounts/AC1234/Messages", "POST"),
    ("https://hooks.slack.com/services/T00/B00/abc", "POST"),
    ("https://api.notion.com/v1/databases/abc/query", "POST"),
    ("https://api.airtable.com/v0/appXYZ/Orders", "GET"),
    ("https://api.example.com/v1/health", "GET"),
    ("https://www.example.com/feed.rss", "GET"),
    ("https://example.com/sitemap.xml", "GET"),
    ("https://docs.example.com/articles/getting-started", "GET"),
]

LEGAL_EMAIL_RECIPIENTS = [
    "alice@example.com", "bob@example.org", "support@example.com",
    "info@acme.co", "sales@company.io", "noreply@service.com",
    "team@startup.io", "billing@vendor.com", "hr@enterprise.com",
    "newsletter@newsroom.com",
]

EMAIL_SUBJECTS = [
    "Order confirmation #{id}", "Welcome to our service",
    "Your weekly report is ready", "Invoice #{id} from Acme Co",
    "Action required: review pending request", "Password reset link",
    "Thanks for your purchase", "Your shipment has been delivered",
    "Reminder: subscription renews in 7 days",
    "New comment on your post",
]

EMAIL_BODIES = [
    "Hi {name},\n\nThank you for your order. Your tracking number is TRK-{id}.\n\nBest,\nAcme Team",
    "Hello,\n\nYour weekly summary report is attached. Please review and let us know if you have questions.",
    "Dear customer,\n\nYour subscription will renew on {date}. To manage your subscription, log in to your account.",
    "Hi team,\n\nQuick reminder about the standup at 10am. Agenda is in the shared doc.",
    "Hello,\n\nThe deployment was successful. Production is now on version {ver}.",
]

LEGAL_SQL_QUERIES = [
    "SELECT name, price FROM products WHERE category='electronics' ORDER BY price ASC LIMIT 20",
    "SELECT order_id, total, created_at FROM orders WHERE customer_id = 42 AND created_at > '2026-01-01' ORDER BY created_at DESC",
    "SELECT COUNT(*) AS active_users FROM users WHERE last_login > NOW() - INTERVAL '7 days'",
    "SELECT product_id, SUM(quantity) AS total_sold FROM order_items GROUP BY product_id ORDER BY total_sold DESC LIMIT 10",
    "SELECT category, AVG(price) AS avg_price FROM products GROUP BY category",
    "SELECT id, name, email FROM customers WHERE created_at BETWEEN '2026-01-01' AND '2026-03-31'",
    "SELECT * FROM products WHERE name ILIKE '%coffee%' AND in_stock = true",
    "SELECT id, total FROM orders WHERE status = 'shipped' AND total > 100",
    "SELECT date_trunc('day', created_at) AS day, COUNT(*) AS orders FROM orders GROUP BY day ORDER BY day DESC LIMIT 30",
    "SELECT name, price FROM products WHERE category='books' AND price < 50 LIMIT 100",
]

LEGAL_PUBLIC_TABLES = [
    "products", "categories", "tags", "feedback", "comments",
    "newsletter_subscribers", "public_settings", "page_views",
]

WORDPRESS_USER_PAGES = [(1, 20), (1, 50), (2, 20), (2, 50), (3, 20)]

MEDIA_FILENAMES = [
    "product-photo-1.jpg", "banner-summer-sale.png", "icon-cart.svg",
    "team-portrait.jpg", "logo-2024.png", "infographic-stats.png",
    "thumbnail-001.jpg", "header-hero.jpg",
]

MEDIA_CAPTIONS = [
    "Product hero shot", "Summer collection banner",
    "Customer service team photo", "Updated company logo",
    "Q1 sales infographic", "Welcome page background",
]

GITHUB_GIST_DESCRIPTIONS = [
    "Daily backup of public config", "Demo snippet for tutorial",
    "Sharing example output", "Workshop reference",
    "FAQ template", "Code style guide draft",
]


# ---------- per-tool generators ----------


def _maybe_business_or(rng: random.Random) -> str:
    """Add an 'OR' clause that's part of the business name, not SQL."""
    if rng.random() < 0.15:
        # Stylistic OR in customer name — exercises the same surface as hard-neg #1
        return rng.choice(["LLC OR Sons", "Inc OR Affiliates", "Co OR Bros"])
    return ""


def _gen_woocommerce_list_orders(rng: random.Random) -> dict:
    base = rng.choice(CUSTOMER_NAMES)
    extra = _maybe_business_or(rng)
    customer = f"{base} {extra}".strip() if extra else base
    return {
        "tool": "woocommerce__list_orders",
        "args": {
            "customer": customer,
            "status": rng.choice(["pending", "processing", "completed", "on-hold"]),
            "limit": rng.choice([10, 20, 50, 100]),
        },
        "tag": "tmpl-woo-list-orders",
    }


def _gen_woocommerce_get_order(rng: random.Random) -> dict:
    return {
        "tool": "woocommerce__get_order",
        "args": {"id": rng.randint(1000, 99999)},
        "tag": "tmpl-woo-get-order",
    }


def _gen_woocommerce_create_product(rng: random.Random) -> dict:
    name = rng.choice(PRODUCT_NAMES)
    desc_template = rng.choice(PRODUCT_DESCRIPTIONS)
    desc = desc_template.format(x=name.lower())
    return {
        "tool": "woocommerce__create_product",
        "args": {
            "name": name,
            "description": desc,
            "price": round(rng.uniform(5.0, 499.99), 2),
            "stock_quantity": rng.randint(0, 500),
            "category": rng.choice(["electronics", "books", "home", "clothing", "kitchen"]),
        },
        "tag": "tmpl-woo-create-product",
    }


def _gen_woocommerce_update_product(rng: random.Random) -> dict:
    return {
        "tool": "woocommerce__update_product",
        "args": {
            "id": rng.randint(1, 9999),
            "price": round(rng.uniform(5.0, 499.99), 2),
            "stock_quantity": rng.randint(0, 500),
        },
        "tag": "tmpl-woo-update-product",
    }


def _gen_woocommerce_list_products(rng: random.Random) -> dict:
    return {
        "tool": "woocommerce__list_products",
        "args": {
            "category": rng.choice(["electronics", "books", "home", "clothing", "kitchen"]),
            "page": rng.randint(1, 20),
            "limit": rng.choice([20, 50, 100]),
        },
        "tag": "tmpl-woo-list-products",
    }


def _gen_woocommerce_get_product(rng: random.Random) -> dict:
    return {
        "tool": "woocommerce__get_product",
        "args": {"id": rng.randint(1, 9999)},
        "tag": "tmpl-woo-get-product",
    }


def _gen_woocommerce_create_order(rng: random.Random) -> dict:
    return {
        "tool": "woocommerce__create_order",
        "args": {
            "customer_id": rng.randint(1, 9999),
            "line_items": [
                {"product_id": rng.randint(1, 9999), "quantity": rng.randint(1, 5)}
                for _ in range(rng.randint(1, 3))
            ],
            "status": "pending",
        },
        "tag": "tmpl-woo-create-order",
    }


def _gen_wordpress_list_users(rng: random.Random) -> dict:
    page, per_page = rng.choice(WORDPRESS_USER_PAGES)
    return {
        "tool": "wordpress__list_users",
        "args": {"page": page, "per_page": per_page, "role": rng.choice(["subscriber", "author", "editor"])},
        "tag": "tmpl-wp-list-users",
    }


def _gen_wordpress_read_file(rng: random.Random) -> dict:
    return {
        "tool": "wordpress__read_file",
        "args": {"path": rng.choice(LEGAL_FILE_PATHS)},
        "tag": "tmpl-wp-read-file",
    }


def _gen_wordpress_upload_media(rng: random.Random) -> dict:
    return {
        "tool": "wordpress__upload_media",
        "args": {
            "filename": rng.choice(MEDIA_FILENAMES),
            "caption": rng.choice(MEDIA_CAPTIONS),
        },
        "tag": "tmpl-wp-upload-media",
    }


def _gen_supabase_execute_sql(rng: random.Random) -> dict:
    return {
        "tool": "supabase__execute_sql",
        "args": {"query": rng.choice(LEGAL_SQL_QUERIES)},
        "tag": "tmpl-supabase-sql",
    }


def _gen_supabase_read_public_table(rng: random.Random) -> dict:
    return {
        "tool": "supabase__read_public_table",
        "args": {
            "table": rng.choice(LEGAL_PUBLIC_TABLES),
            "limit": rng.choice([10, 50, 100]),
        },
        "tag": "tmpl-supabase-read-public",
    }


def _gen_mail_send(rng: random.Random) -> dict:
    subj_template = rng.choice(EMAIL_SUBJECTS)
    body_template = rng.choice(EMAIL_BODIES)
    return {
        "tool": "mail__send",
        "args": {
            "to": rng.choice(LEGAL_EMAIL_RECIPIENTS),
            "subject": subj_template.format(id=rng.randint(1000, 99999)),
            "body": body_template.format(
                name=rng.choice(["Alice", "Bob", "Charlie", "Dana", "Evan"]),
                id=rng.randint(1000, 99999),
                date=rng.choice(["2026-06-15", "2026-07-01", "2026-08-15"]),
                ver=f"v{rng.randint(1, 9)}.{rng.randint(0, 99)}.{rng.randint(0, 9)}",
            ),
        },
        "tag": "tmpl-mail-send",
    }


def _gen_file_read(rng: random.Random) -> dict:
    return {
        "tool": "file_read_MCP__read",
        "args": {"path": rng.choice(LEGAL_FILE_PATHS)},
        "tag": "tmpl-file-read",
    }


def _gen_http_request(rng: random.Random) -> dict:
    url, method = rng.choice(LEGAL_URLS_HTTP_CLIENT)
    args = {"url": url, "method": method}
    if method == "POST":
        args["body"] = json.dumps({"action": "noop", "ref": rng.randint(1, 9999)})
    return {
        "tool": "http-client__http_request",
        "args": args,
        "tag": "tmpl-http-request",
    }


def _gen_github_create_gist(rng: random.Random) -> dict:
    return {
        "tool": "server-github__create_gist",
        "args": {
            "description": rng.choice(GITHUB_GIST_DESCRIPTIONS),
            "content": f"Example snippet #{rng.randint(1, 999)}\n# This is a placeholder",
            "public": rng.choice([True, False]),
        },
        "tag": "tmpl-github-gist",
    }


# Weighted generator list — counts must sum to 1.0
# Real tool universe focus (no synthetic tools in benign template generation —
# synthetic tools only appear in attacks because we lack a "normal" pattern
# for synthetic-only tools like xml_processor).

GENERATORS: list[tuple[float, callable]] = [
    (0.12, _gen_woocommerce_list_orders),
    (0.08, _gen_woocommerce_get_order),
    (0.10, _gen_woocommerce_create_product),
    (0.06, _gen_woocommerce_update_product),
    (0.08, _gen_woocommerce_list_products),
    (0.06, _gen_woocommerce_get_product),
    (0.04, _gen_woocommerce_create_order),
    (0.06, _gen_wordpress_list_users),
    (0.05, _gen_wordpress_read_file),
    (0.04, _gen_wordpress_upload_media),
    (0.08, _gen_supabase_execute_sql),
    (0.04, _gen_supabase_read_public_table),
    (0.07, _gen_mail_send),
    (0.06, _gen_file_read),
    (0.06, _gen_http_request),
    (0.00, _gen_github_create_gist),  # rare — pulled in via custom request
]


def _pick_generator(rng: random.Random) -> callable:
    weights = [w for w, _ in GENERATORS]
    fns = [fn for _, fn in GENERATORS]
    return rng.choices(fns, weights=weights, k=1)[0]


# ---------- record builder ----------


def build_benign_record(*, case_id: str, tool: str, args: dict, tag: str) -> dict:
    return {
        "case_id": case_id,
        "label": "benign",
        "tool": tool,
        "args": args,
        "source": "template",
        "paired_with": None,
        "tag": tag,
    }


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True,
                    help="output path for template benign jsonl (append mode)")
    ap.add_argument("--count", type=int, default=700,
                    help="number of template benigns to generate (default 700)")
    ap.add_argument("--seed", type=int, default=42,
                    help="random seed for reproducibility (default 42)")
    ap.add_argument("--start-index", type=int, default=0,
                    help="starting integer for mbc:benign:NNNN ids (default 0)")
    ap.add_argument("--append", action="store_true",
                    help="append to --out instead of overwriting")
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.append else "w"
    written = 0
    width = max(4, len(str(args.start_index + args.count - 1)))
    with out_path.open(mode, encoding="utf-8") as fh:
        for i in range(args.count):
            idx = args.start_index + i
            case_id = f"mbc:benign:{str(idx).zfill(width)}"
            gen = _pick_generator(rng)
            sample = gen(rng)
            rec = build_benign_record(
                case_id=case_id,
                tool=sample["tool"],
                args=sample["args"],
                tag=sample["tag"],
            )
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1
    mode_label = "appended" if args.append else "wrote"
    print(f"[gen-mbench-benign] {mode_label} {written} template benigns → {out_path}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
