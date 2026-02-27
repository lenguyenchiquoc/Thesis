from playwright.async_api import async_playwright
import asyncio
from urllib.parse import urlparse, parse_qs

class BrowserScanner:
    def __init__ (self, target_url, headless = True, timeout = 1000):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.ignore_ext = {"jpg", "jpeg", "png", "gif", "css", "js", "svg", "mp4", "mp3"}
        self.headless = headless
        self.timeout = timeout
        self.vectors = []
        
    async def start(self):
        async with async_playwright() as a:
            browser = await a.chromium.launch(headless = self.headless)
            context = await browser.new_context()
            page = await context.new_page()
            
            page.on("request", self._handle_request)
            
            await page.goto(self.target_url)
            await page.wait_for_timeout(self.timeout)
            
            await browser.close()
        return self.vectors
    
    def _handle_request(self, request):

        url = request.url
        method = request.method

        parsed = urlparse(url)
        
        if parsed.netloc != self.base_domain:
            return
        
        path = parsed.path
        if "." in path:
            ext = path.split(".")[-1].lower()
            if ext in self.ignore_ext:
                return
        query_params = parse_qs(parsed.query)

        for name, values in query_params.items():
            for value in values:
                self.vectors.append({
                    "source": "browser",
                    "url": url,
                    "method": method,
                    "location": "url_param",
                    "name": name,
                    "value": value
                })

        for name, value in request.headers.items():
            self.vectors.append({
                "source": "browser",
                "url": url,
                "method": method,
                "location": "header",
                "name": name,
                "value": value
            })

        post_data = request.post_data
        if post_data:
            self.vectors.append({
                "source": "browser",
                "url": url,
                "method": method,
                "location": "raw_body",
                "name": "payload",
                "value": post_data
            })        