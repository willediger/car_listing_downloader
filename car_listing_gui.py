#!/usr/bin/env python3
import os, re, pathlib, threading, queue, urllib.parse, zipfile, shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

DEFAULT_OUT = r"C:\Users\willh\Projects\car_listing_downloader\out"

IMAGE_MIN_BYTES = 80_000
NEXT_SELECTORS = [
    '[aria-label="Next"]','[aria-label="next"]',
    'button[aria-label="Next"]','button[title="Next"]','button:has-text("Next")',
    '.slick-next','.swiper-button-next','.gallery-next','[data-action="next"]',
    '.next','a.next','.bx-next','a[title="Next"]'
]

IMG_EXT_RE = re.compile(r'\.(?:jpg|jpeg|png|webp)(?:[?#].*)?$', re.I)
ABS_IMG_IN_TEXT_RE = re.compile(r'https?://[^\s"\'<>]+?\.(?:jpg|jpeg|png|webp)(?:\?[^\s"\'<>]*)?', re.I)

def sanitize(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', name).strip('_')[:64] or "listing"

def is_img_url(u: str) -> bool:
    return bool(IMG_EXT_RE.search(u or ""))

def resolve(base: str, u: str) -> str:
    if not u: return ""
    if u.startswith("//"): return "https:" + u
    return urllib.parse.urljoin(base, u)

def promote_resolution(u: str) -> str:
    # Generic size bumps in path and query
    u = re.sub(r"/(\d{3,4})/(\d{3,4})/", "/1920/1080/", u)
    pr = urllib.parse.urlsplit(u)
    if pr.query:
        parts = urllib.parse.parse_qsl(pr.query, keep_blank_values=True)
        upd = []
        for k,v in parts:
            kl = k.lower()
            if kl in ("w","width"): v = "1920"
            elif kl in ("h","height"): v = "1080"
            elif kl in ("q","quality"): v = "100"
            upd.append((k,v))
        u = urllib.parse.urlunsplit((pr.scheme, pr.netloc, pr.path, urllib.parse.urlencode(upd, doseq=True), pr.fragment))
    if "promaxinventory.com" in u.lower():
        u = u.replace("/thumb/", "/").replace("/small/", "/")
        u = re.sub(r"/(\d{2,4})x(\d{2,4})/", "/1920x1080/", u)
    return u

def collect_src_srcset_href_attrs(ctx):
    js = """
    () => {
      const urls = new Set();
      const attrs = ["src","data-src","data-lazy","data-original","data-zoom-image","data-large","data-src-large","data-full","data-image","data-img","href","content","data-href"];
      const add = v => { if (v) urls.add(v); };
      document.querySelectorAll("img,source,a,meta,link,div,li").forEach(el=>{
        for (const a of attrs) { const v = el.getAttribute && el.getAttribute(a); if (v) urls.add(v); }
      });
      document.querySelectorAll("img[srcset],source[srcset]").forEach(el=>{
        const ss = el.getAttribute("srcset"); if (!ss) return;
        for (const part of ss.split(",")) { const u = part.trim().split(/\\s+/)[0]; if (u) urls.add(u); }
      });
      document.querySelectorAll("[style]").forEach(el=>{
        const st = el.getAttribute("style");
        const m = st && st.match(/url\\((['"]?)(.*?)\\1\\)/);
        if (m && m[2]) urls.add(m[2]);
      });
      return Array.from(urls);
    }
    """
    try:
        return set(ctx.evaluate(js) or [])
    except Exception:
        return set()

def collect_best_srcset(ctx):
    urls = set()
    try:
        for img in ctx.query_selector_all("img,source"):
            src = img.get_attribute("src")
            if src: urls.add(resolve(ctx.url, src))
            srcset = img.get_attribute("srcset")
            if not srcset: continue
            cands = []
            for p in [x.strip() for x in srcset.split(",")]:
                if not p: continue
                toks = p.split()
                u = resolve(ctx.url, toks[0])
                w = 0
                if len(toks) > 1 and toks[1].endswith("w"):
                    try: w = int(toks[1][:-1])
                    except: w = 0
                cands.append((w,u))
            if cands:
                cands.sort(reverse=True)
                urls.add(cands[0][1])
    except Exception:
        pass
    return urls

def collect_text_links(html: str):
    return set(ABS_IMG_IN_TEXT_RE.findall(html or ""))

def collect_anchor_directs(ctx):
    try:
        hrefs = ctx.evaluate("() => Array.from(document.querySelectorAll('a[href]'), a => a.href)")
    except Exception:
        return set()
    return set(h for h in hrefs if is_img_url(h))

def harvest_ctx(ctx):
    base = ctx.url
    urls = set()
    try:
        html = ctx.content()
    except Exception:
        html = ""
    for u in collect_text_links(html): urls.add(resolve(base, u))
    for u in collect_src_srcset_href_attrs(ctx): urls.add(resolve(base, u))
    for u in collect_best_srcset(ctx): urls.add(resolve(base, u))
    for u in collect_anchor_directs(ctx): urls.add(resolve(base, u))
    final = set()
    for u in urls:
        if is_img_url(u):
            final.add(promote_resolution(u))
    return final

def try_open_gallery(page):
    candidates = [
        "a:has-text('Photos')", "a:has-text('View Photos')", "a:has-text('View All')", "a:has-text('Gallery')",
        ".vehicle-image img", "#mainImage img", "#vehicle img", ".photos img", ".gallery img",
        "img[src*='promaxinventory.com']"
    ]
    for sel in candidates:
        loc = page.locator(sel)
        if loc.count():
            try:
                loc.first.click()
                page.wait_for_timeout(600)
                return True
            except Exception:
                continue
    return False

def click_thumbnails(ctx):
    sels = ["ul#images li img", ".bx-viewport img", ".thumbnails img", ".thumbs img"]
    for sel in sels:
        try:
            loc = ctx.locator(sel)
            n = loc.count()
            if n:
                for i in range(min(n, 80)):
                    try:
                        loc.nth(i).click()
                        ctx.wait_for_timeout(150)
                    except Exception:
                        pass
        except Exception:
            pass

def download_url(context, referer, url, dest_dir, saved, logger):
    try:
        if url in saved: return
        r = context.request.get(url, headers={"Referer": referer})
        if not r.ok: return
        body = r.body()
        if not body or len(body) < IMAGE_MIN_BYTES: return
        idx = len(saved) + 1
        ct = r.headers.get("content-type", "")
        ext = ".jpg"
        ul = url.lower()
        if "png" in ct or ul.endswith(".png"): ext = ".png"
        elif "webp" in ct or ul.endswith(".webp"): ext = ".webp"
        fname = os.path.join(dest_dir, f"{idx:03d}{ext}")
        with open(fname, "wb") as f: f.write(body)
        saved[url] = fname
        logger(f"Saved {os.path.basename(fname)}")
    except Exception as e:
        logger(f"Fetch error: {e}")

def download_listings(urls, outdir, max_clicks, headful, logger, stop_event):
    os.makedirs(outdir, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headful)
        context = browser.new_context()
        for url in urls:
            if stop_event.is_set(): logger("Stopped"); break
            page = context.new_page()
            page.set_default_timeout(15000)
            logger(f"Fetching {url}")
            try:
                page.goto(url, wait_until="load")
                try: page.wait_for_load_state("networkidle", timeout=10000)
                except PWTimeout: pass
            except Exception as e:
                logger(f"Open failed: {e}"); page.close(); continue

            folder = sanitize(page.title() or urllib.parse.urlparse(url).path.split("/")[-1])
            tmp_dir = os.path.join(outdir, folder)
            pathlib.Path(tmp_dir).mkdir(parents=True, exist_ok=True)

            saved = {}
            inflight = set()

            def on_response(resp):
                try:
                    ct = resp.headers.get("content-type", "")
                    if not ct or not ct.startswith("image/"): return
                    u = resp.url.lower()
                    if any(x in u for x in ["thumb", "sprite", "icon"]): return
                    if resp.url in saved or resp.url in inflight: return
                    inflight.add(resp.url)
                    body = resp.body()
                    if not body or len(body) < IMAGE_MIN_BYTES: return
                    idx = len(saved) + 1
                    ext = ".jpg"
                    if "png" in ct or u.endswith(".png"): ext = ".png"
                    elif "webp" in ct or u.endswith(".webp"): ext = ".webp"
                    fname = os.path.join(tmp_dir, f"{idx:03d}{ext}")
                    with open(fname, "wb") as f: f.write(body)
                    saved[resp.url] = fname
                    logger(f"Saved {os.path.basename(fname)}")
                except Exception as e:
                    logger(f"Resp error: {e}")
                finally:
                    inflight.discard(resp.url)

            page.on("response", on_response)

            # Scroll to trigger lazy loads
            try: height = page.evaluate("() => document.body.scrollHeight")
            except: height = 4000
            y = 0
            while y < height and not stop_event.is_set():
                page.mouse.wheel(0, 800); y += 800; page.wait_for_timeout(120)

            # Open the gallery if present, then click next and thumbnails
            try_open_gallery(page)
            click_thumbnails(page)

            def try_click_next():
                for sel in NEXT_SELECTORS:
                    loc = page.locator(sel)
                    if loc.count():
                        try: loc.first.click(); return True
                        except: pass
                return False

            clicks = 0; last = 0; stale = 0
            while clicks < max_clicks and not stop_event.is_set():
                if not try_click_next(): break
                clicks += 1
                page.wait_for_timeout(350)
                if len(saved) == last: stale += 1
                else: stale = 0; last = len(saved)
                if stale >= 6: break

            # Harvest from page and all frames
            for u in harvest_ctx(page):
                if stop_event.is_set(): break
                download_url(context, page.url, u, tmp_dir, saved, logger)
            for fr in page.frames:
                for u in harvest_ctx(fr):
                    if stop_event.is_set(): break
                    download_url(context, page.url, u, tmp_dir, saved, logger)

            page.close()
            if saved:
                zip_path = os.path.join(outdir, f"{folder}.zip")
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    for fpath in sorted(saved.values()):
                        zf.write(fpath, arcname=os.path.basename(fpath))
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger(f"Zipped: {zip_path}")
            else:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger("No images found")

        browser.close()

class App:
    def __init__(self, root):
        self.root = root
        root.title("Car Listing Image Zipper")
        root.geometry("720x520")
        self.log_q = queue.Queue()
        self.worker = None
        self.stop_event = threading.Event()

        frm = ttk.Frame(root, padding=10); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Listing URLs (one per line):").pack(anchor="w")
        self.txt_urls = tk.Text(frm, height=6); self.txt_urls.pack(fill="x"); self.txt_urls.insert("1.0", "")

        path_row = ttk.Frame(frm); path_row.pack(fill="x", pady=(8,0))
        ttk.Label(path_row, text="Output folder:").pack(side="left")
        self.out_var = tk.StringVar(value=DEFAULT_OUT)
        self.out_entry = ttk.Entry(path_row, textvariable=self.out_var, width=70)
        self.out_entry.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(path_row, text="Browse", command=self.choose_dir).pack(side="left")

        opts = ttk.Frame(frm); opts.pack(fill="x", pady=(8,0))
        self.headful_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Show browser", variable=self.headful_var).pack(side="left")
        ttk.Label(opts, text="Max clicks:").pack(side="left", padx=(12,4))
        self.max_clicks = tk.IntVar(value=60)
        ttk.Spinbox(opts, from_=10, to=200, textvariable=self.max_clicks, width=6).pack(side="left")

        btns = ttk.Frame(frm); btns.pack(fill="x", pady=(8,0))
        self.start_btn = ttk.Button(btns, text="Start", command=self.start); self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop, state="disabled"); self.stop_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="Open output", command=self.open_out).pack(side="left", padx=6)

        ttk.Label(frm, text="Log:").pack(anchor="w", pady=(8,0))
        self.log = tk.Text(frm, height=16, state="disabled"); self.log.pack(fill="both", expand=True)
        self.root.after(100, self.flush_logs)

    def choose_dir(self):
        d = filedialog.askdirectory(initialdir=self.out_var.get() or DEFAULT_OUT)
        if d: self.out_var.set(d)

    def open_out(self):
        d = self.out_var.get() or DEFAULT_OUT
        pathlib.Path(d).mkdir(parents=True, exist_ok=True)
        if os.name == "nt": os.startfile(d)
        else: messagebox.showinfo("Info", "Folder: {}".format(d))

    def start(self):
        urls = [u.strip() for u in self.txt_urls.get("1.0", "end").splitlines() if u.strip()]
        if not urls:
            messagebox.showerror("Error", "Add at least one URL."); return
        outdir = self.out_var.get().strip() or DEFAULT_OUT
        maxc = int(self.max_clicks.get()); headful = self.headful_var.get()
        self.stop_event.clear(); self.start_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        with self.log_q.mutex: self.log_q.queue.clear()
        self._append("Starting...\n")

        def logger(msg): self.log_q.put(msg)
        def work():
            try: download_listings(urls, outdir, maxc, headful, logger, self.stop_event)
            except Exception as e: logger("Fatal: {}".format(e))
            finally: self.root.after(0, self.done)
        self.worker = threading.Thread(target=work, daemon=True); self.worker.start()

    def stop(self):
        self.stop_event.set(); self._append("Stop requested\n")

    def done(self):
        self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled"); self._append("Done\n")

    def flush_logs(self):
        try:
            while True:
                msg = self.log_q.get_nowait(); self._append(msg + "\n")
        except queue.Empty:
            pass
        self.root.after(150, self.flush_logs)

    def _append(self, text):
        self.log.config(state="normal"); self.log.insert("end", text); self.log.see("end"); self.log.config(state="disabled")

if __name__ == "__main__":
    try:
        root = tk.Tk(); App(root); root.mainloop()
    except Exception as e:
        print("GUI error: {}".format(e))
