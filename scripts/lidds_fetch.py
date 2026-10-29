"""Download archives from a public Proton Drive share with headless Chromium (Proton decrypts in the browser).
Used on .234 for LID-DS 2021 (25/10) and LID-DS 2019 (30/10); needs a Playwright venv (/home/dat/.venvs/playwright).

    python lidds_fetch.py URL list            print every file of the share with its size
    python lidds_fetch.py URL get NAME...     download the named files into the current directory (skips complete files)

LID-DS 2021: https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm   LID-DS 2019: https://drive.proton.me/urls/4DCRHJC9XC#pn6TukLN0Wq5
(links from the LID-DS README, github.com/LID-DS/LID-DS)
"""
import asyncio, re, sys, time
from pathlib import Path
from playwright.async_api import async_playwright


async def rows(page):
    seen = {}
    for _ in range(40):
        text = await page.inner_text("body")
        for m in re.finditer(r"^(\S+\.zip)\n\1\n([\d.]+ [KMGT]?B)$", text, re.M):
            seen[m.group(1)] = m.group(2)
        await page.mouse.wheel(0, 4000)
        await page.wait_for_timeout(1500)
        if "Loading" not in text and len(seen) >= 1:
            break
    return seen


async def main():
    url, cmd, names = sys.argv[1], sys.argv[2], sys.argv[3:]
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        ctx = await b.new_context(accept_downloads=True)
        page = await ctx.new_page()
        await page.goto(url, wait_until="networkidle", timeout=180000)
        await page.wait_for_selector("text=.zip", timeout=180000)
        listing = await rows(page)
        if cmd == "list":
            for k, v in sorted(listing.items()):
                print(f"{k}\t{v}")
            print("files", len(listing))
        else:
            for name in names:
                target = Path(name)
                if target.exists() and target.stat().st_size > 0:
                    print("have", name); continue
                row = page.locator("tr", has=page.locator(f'[data-testid="name-cell"][aria-label="{name}"]')).first
                await row.scroll_into_view_if_needed()
                t0 = time.time()
                async with page.expect_download(timeout=0) as info:
                    await row.get_by_role("button", name="Download").click()
                d = await info.value
                await d.save_as(str(target))
                print("saved", name, target.stat().st_size, "bytes in", round(time.time() - t0), "s", flush=True)
        await b.close()

asyncio.run(main())
