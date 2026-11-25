from playwright.sync_api import sync_playwright
import pprint

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={'width': 1366, 'height': 768})
    page.goto('http://localhost:8501?auth=signin', wait_until='networkidle')
    page.wait_for_timeout(1000)

    res = page.evaluate("""() => {
        const root = document.querySelector('[data-testid="stTextInputRootElement"]');
        const rootChildren = Array.from(root.querySelectorAll('*')).map(el => {
            const cs = getComputedStyle(el);
            const r = el.getBoundingClientRect();
            return {
                tag: el.tagName,
                testid: el.getAttribute('data-testid'),
                baseweb: el.getAttribute('data-baseweb'),
                cls: el.className,
                w: Math.round(r.width),
                display: cs.display,
                flex: cs.flex,
                widthCss: cs.width,
            };
        });
        const card = document.querySelector('.hc-card');
        const cardCs = getComputedStyle(card);
        return {
            rootHtml: root.outerHTML,
            rootChildren,
            cardHtml: card.outerHTML,
            cardDisplay: cardCs.display,
            cardFlexDir: cardCs.flexDirection,
            cardChildren: Array.from(card.children).map(c => ({tag: c.tagName, display: getComputedStyle(c).display, text: c.textContent})),
        };
    }""")
    pprint.pprint(res)
    browser.close()
