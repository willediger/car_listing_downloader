#!/usr/bin/env python3
import argparse, os, re, pathlib, urllib.parse
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

IMAGE_MIN_BYTES = 120_000  # skip thumbnails

NEXT_SELECTORS = [
    '[aria-label="Next"]',
    '[aria-label="next"]',
    'button[aria-label="Next"]',
    'button[title="Next"]',
    'button:has-text("Next")',
    '.slick-next',
    '.swiper-button-next',
    '.gallery-next',
    '[data-action="next"]',
    '.next',
    'a.next',
]

def sanitize(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', name).strip('_')[:64] or "listing"

def collect_srcset_urls(page):
    urls = set()
    for img in page.query_selector_all("img"):
        src = img.get_attribute("src")
        if src:
            urls.add(urllib.parse.urljoin(page.url, src))
        srcset = img.get_attribute("srcset")
        if not srcset:
            continue
        parts = [p.strip() for p in srcset.split(",")]
        candidates = []
        for p in parts:
            toks = p.split()
            if not toks:
                continue
            u = urllib.parse.urljoin(page.url, toks[0])
            w = 0
            if len(toks) > 1 and toks[1].endswith("w"):
                try:
                    w = int(toks[1][:-1])
                except:
                    w = 0
            candidates.append((w, u))
        if candidates:
            candidates.sort(reverse=True)
            urls.add(candidates[0][1])
    return urls

def main():
    ap = argparse.ArgumentParser(description="Download full gallery images from car listings")
    ap.add_argument("urls", nargs="+", help="Listing URLs")
    ap.add_argument("-o", "--outdir", default="car_images")
    ap.add_argument("--max-clicks", type=int, default=60)
    ap.add_argument("--headful", action="store_true", help="Show the browser window")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headful)
        context = browser.new_context()
        for url in args.urls:
            page = context.new_page()
            page.set_default_timeout(15000)

            print(f"Fetching {url}")
            page.goto(url, wait_until="load")
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except PWTimeout:
                pass

            folder = sanitize(page.title() or urllib.parse.urlparse(url).path.split("/")[-1])
            dest = os.path.join(args.outdir, folder)
            pathlib.Path(dest).mkdir(parents=True, exist_ok=True)

            saved = {}
            inflight = set()

            def on_response(resp):
                try:
                    ct = resp.headers.get("content-type", "")
                    if not ct.startswith("image/"):
                        return
                    u = resp.url
                    ul = u.lower()
                    if any(x in ul for x in ["thumb", "thumbnail", "small", "icon", "sprite"]):
                        return
                    if u in saved or u in inflight:
                        return
                    inflight.add(u)
                    body = resp.body()
                    if not body or len(body) < IMAGE_MIN_BYTES:
                        return
                    idx = len(saved) + 1
                    ext = ".jpg"
                    if "image/png" in ct or ul.endswith(".png"):
                        ext = ".png"
                    elif "image/webp" in ct or ul.endswith(".webp"):
                        ext = ".webp"
                    fname = os.path.join(dest, f"{idx:03d}{ext}")
                    with open(fname, "wb") as f:
                        f.write(body)
                    saved[u] = fname
                    print(f"Saved {fname}")
                finally:
                    inflight.discard(resp.url)

            page.on("response", on_response)

            # Expose as many images as possible
            # 1) Scroll to trigger lazy loads
            try:
                height = page.evaluate("() => document.body.scrollHeight")
            except:
                height = 4000
            for _ in range(0, height, 600):
                page.mouse.wheel(0, 600)
                page.wait_for_timeout(200)

            # 2) Click common "next" controls
            def try_click_next():
                for sel in NEXT_SELECTORS:
                    loc = page.locator(sel)
                    if loc.count():
                        try:
                            loc.first.click()
                            return True
                        except:
                            pass
                return False

            clicks = 0
            last_count = 0
            stale_advance = 0
            while clicks < args.max_clicks:
                if not try_click_next():
                    break
                clicks += 1
                page.wait_for_timeout(500)
                if len(saved) == last_count:
                    stale_advance += 1
                else:
                    stale_advance = 0
                    last_count = len(saved)
                if stale_advance >= 5:
                    break

            # 3) Fallback: pull highest srcset candidates directly
            for u in collect_srcset_urls(page):
                if u in saved:
                    continue
                try:
                    r = context.request.get(u, headers={"Referer": page.url})
                    if not r.ok:
                        continue
                    body = r.body()
                    if not body or len(body) < IMAGE_MIN_BYTES:
                        continue
                    idx = len(saved) + 1
                    ct = r.headers.get("content-type", "")
                    ext = ".jpg"
                    ul = u.lower()
                    if "image/png" in ct or ul.endswith(".png"):
                        ext = ".png"
                    elif "image/webp" in ct or ul.endswith(".webp"):
                        ext = ".webp"
                    fname = os.path.join(dest, f"{idx:03d}{ext}")
                    with open(fname, "wb") as f:
                        f.write(body)
                    saved[u] = fname
                    print(f"Saved {fname} from srcset")
                except Exception as e:
                    print(f"Fetch error: {e}")

            page.close()
            print(f"Done. {len(saved)} images saved to {dest}")
        browser.close()

if __name__ == "__main__":
    main()
