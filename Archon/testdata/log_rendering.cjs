const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

// Minimal DOM with textContent/HTML serialization. Real Chromium exercises the
// same source separately; this fixture keeps the regression runnable with Node.
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
class Element {
    constructor(tag) { this.tag = tag; this.children = []; this._html = ''; this._text = ''; this.className = ''; this.value = ''; }
    set textContent(value) { this.children = []; this._html = ''; this._text = String(value); }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set innerHTML(value) { this.children = []; this._text = ''; this._html = value; }
    get innerHTML() { return this._html + escape(this._text) + this.children.map(child => child.outerHTML).join(''); }
    get outerHTML() { return this.tag === '#text' ? escape(this._text) : `<${this.tag} class="${escape(this.className)}">${this.innerHTML}</${this.tag}>`; }
    appendChild(child) { this.children.push(child); return child; }
    append(...children) { for (const child of children) this.appendChild(child); }
    replaceChildren(...children) { this.children = []; this._html = ''; this._text = ''; this.append(...children); }
    querySelector() { return null; }
}
const elements = new Map();
const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div')); return elements.get(id); },
    createElement(tag) { return new Element(tag); },
    createTextNode(text) { const node = new Element('#text'); node.textContent = text; return node; }
};
const page = fs.readFileSync('web/logs.html', 'utf8');
const shared = fs.readFileSync('web/static/shared.js', 'utf8');
const extract = (source, start, end) => {
    const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
    assert(a >= 0 && b > a, `Missing source boundary ${start}`);
    return source.slice(a, b);
};
const code = extract(shared, 'function escapeHtml(text)', '/**') +
    extract(page, 'function updateStats()', 'function filterLogs()') +
    extract(page, 'function escapeRegExp(', 'function toggleAutoScroll()') +
    extract(page, 'function appendLogEntry(', '// Live log streaming');
const context = vm.createContext({ document, console, icons: {listDashes:''} });
vm.runInContext(`let allLogs=[]; const autoScroll=false; ${code}`, context);
const level = '<em data-fixture=metadata>inert-marker</em>';
context.entry = { timestamp: '<em>timestamp</em>', level, message: 'needle <em>message</em>' };
vm.runInContext('allLogs=[entry]; renderLogs();', context);
let html = document.getElementById('logViewer').innerHTML;
assert(!/<em\b/i.test(html), 'bulk rendering interpreted metadata as HTML');
assert(/log-level info/.test(html), 'unknown level did not fall back to safe INFO enum');
document.getElementById('logViewer').replaceChildren();
vm.runInContext('allLogs=[]; appendLogEntry(entry);', context);
html = document.getElementById('logViewer').innerHTML;
assert(!/<em\b/i.test(html), 'live append interpreted metadata as HTML');
assert(/log-level info/.test(html), 'live append used an unvalidated severity class');
document.getElementById('searchInput').value = 'needle';
vm.runInContext("allLogs=[{timestamp:'fixture',level:'WARNING',message:'Needle <em>literal</em>'}]; renderLogs();", context);
html = document.getElementById('logViewer').innerHTML;
assert(/log-level warn/.test(html), 'WARNING alias lost its warning class');
assert(/class="highlight">Needle<\/span>/.test(html), 'case-insensitive highlighting regressed');
assert(!/<em\b/i.test(html), 'highlighting interpreted literal message markup');
console.log('bulk/live metadata stays text; severity allowlist and highlighting pass');
