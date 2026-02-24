const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const projectsHtml = `<div class="project-card" style="animation: fadeIn 0.4s ease-out 0s forwards; opacity: 0;"><div class="project-top"><div class="project-info"><h3>test</h3><div class="project-path">/test</div></div><div class="project-actions"><button class="scan-now-btn" data-action="scan" data-path="L3Rlc3Q=">⚡ Scan Now</button><button class="remove-btn" data-action="remove" data-path="L3Rlc3Q=">✕</button></div></div></div>`;

console.log(DOMPurify.sanitize(projectsHtml, { ADD_ATTR: ['target', 'data-action', 'data-path', 'data-target', 'id', 'href', 'class', 'style'] }));
