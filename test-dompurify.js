const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const html = '<div class="history-section"><button class="history-toggle" data-action="toggle">📂 1 past scan ▸</button><div class="history-list"><div class="history-item"><span class="date">2/24/2026</span><a href="/reports/foo.html" target="_blank">View Report</a></div></div></div>';

const clean = DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id'] });
console.log(clean);
