import { icons } from './vendor/lucide.js?v=__V__';

// Only trusted, bundled Lucide geometry is used; labels never become SVG markup.
export function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const attrs = { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8,
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false', class: 'icon ' + cls };
  for (const [key, value] of Object.entries(attrs)) svg.setAttribute(key, value);
  for (const [tag, props] of icons[name] || icons.circleHelp) {
    const child = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(props)) child.setAttribute(key, value);
    svg.append(child);
  }
  return svg;
}
