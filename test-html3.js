const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const html = '<div style="animation: fadeIn 0.4s ease-out 0s forwards; opacity: 0;">Test</div>';
console.log(DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id', 'href', 'class', 'style'] }));
