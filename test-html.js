const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const projectsHtml = '<div class="history-section"><button class="history-toggle" data-action="toggle">📂 1 past scan</button><div class="history-list"><div class="history-item"><span class="date">date</span><a href="/reports/file.html" target="_blank">View Report</a></div></div></div>';

console.log(DOMPurify.sanitize(projectsHtml, { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id', 'href', 'class', 'style'] }));
