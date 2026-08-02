/* 5GC-Vuln-Atlas — rendering */
(function () {
  'use strict';

  const { metadata, vulnerabilities } = VULN_DATA;

  /* ===== Hero Stats ===== */
  document.getElementById('stat-total').textContent = metadata.total;
  document.getElementById('stat-vendors').textContent = 7;
  document.getElementById('stat-protocols').textContent = metadata.protocols.length;
  const cveCount = vulnerabilities.filter(v => v.cve).length;
  document.getElementById('stat-cves').textContent = cveCount;

  /* ===== Render Vuln List ===== */
  renderVulnList(vulnerabilities);
  renderTOC(vulnerabilities);

  /* Deep-link: jump to anchor on load */
  if (location.hash) {
    setTimeout(() => {
      const el = document.getElementById(location.hash.slice(1));
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
  }

  /* ================================================================ */

  /* ===== Render TOC ===== */
  function renderTOC(filtered) {
    const tocList = document.getElementById('toc-list');
    const grouped = groupByVendorProtocol(filtered);
    let html = '';

    for (const [vendor, protocols] of Object.entries(grouped)) {
      const vendorCount = Object.values(protocols).reduce((s, arr) => s + arr.length, 0);
      html += `<li><a href="#group-${vendor}" class="toc-vendor">
        ${metadata.vendor_display[vendor]}
        <span class="toc-count">${vendorCount}</span>
      </a><ul>`;
      for (const [proto, items] of Object.entries(protocols)) {
        html += `<li><a href="#group-${vendor}-${proto}" class="toc-protocol">
          ${metadata.protocol_display[proto]}
          <span class="toc-count">${items.length}</span>
        </a></li>`;
      }
      html += '</ul></li>';
    }
    tocList.innerHTML = html;
  }

  /* ===== Render Vuln List ===== */
  function renderVulnList(filtered) {
    const container = document.getElementById('vuln-list');
    const grouped = groupByVendorProtocol(filtered);
    let html = '';

    for (const [vendor, protocols] of Object.entries(grouped)) {
      html += `<div class="vendor-group" id="group-${vendor}">`;
      html += `<h2 class="vendor-heading">${metadata.vendor_display[vendor]}</h2>`;

      for (const [proto, items] of Object.entries(protocols)) {
        html += `<h3 class="protocol-heading" id="group-${vendor}-${proto}">${metadata.protocol_display[proto]} Protocol Vulnerabilities</h3>`;

        items.forEach(v => {
          html += renderCard(v);
        });
      }
      html += '</div>';
    }

    container.innerHTML = html;

    // Apply syntax highlighting (safe: skip if hljs not loaded)
    if (typeof hljs !== 'undefined') {
      container.querySelectorAll('pre code').forEach(block => {
        hljs.highlightElement(block);
      });
    }

    // Highlight vulnerability annotation lines (// ^)
    container.querySelectorAll('pre code').forEach(block => {
      const lines = block.innerHTML.split('\n');
      block.innerHTML = lines.map(line => {
        if (/\/\/\s*\^/.test(stripTags(line)) || /\/\*.*\^/.test(stripTags(line))) {
          return `<span class="vuln-line">${line}</span>`;
        }
        return line;
      }).join('\n');
    });
  }

  function renderCard(v) {
    const patternClass = `badge-${v.pattern}`;
    const cardStyle = `pattern-${v.pattern}`;

    let html = `<div class="vuln-card ${cardStyle}" id="${v.anchor}">`;

    // Header: CVE ID or Vuln-ID as title + badges
    const displayId = v.cve || v.id;
    html += '<div class="vuln-header">';
    html += '<span class="vuln-title">';
    if (v.issue_url && v.issue_url !== 'vulnDB') {
      html += `<a href="${escHtml(v.issue_url)}" target="_blank" rel="noopener">${escHtml(displayId)}</a>`;
    } else {
      html += escHtml(displayId);
    }
    html += '</span>';
    html += `<span class="badge badge-pattern ${patternClass}">${escHtml(v.pattern_display || v.pattern)}</span>`;
    if (v.crash_type) {
      html += `<span class="badge badge-crash">${escHtml(v.crash_type)}</span>`;
    }
    if (v.cwe) {
      html += `<span class="badge badge-cwe">${escHtml(v.cwe.split('/')[0].trim())}</span>`;
    }
    html += '</div>';

    // Meta line
    html += '<div class="vuln-meta">';
    if (v.cve) html += `<span><strong>${escHtml(v.cve)}</strong></span>`;
    if (v.target) html += `<span>Target: ${escHtml(v.target)}</span>`;
    if (v.issue_url && v.issue_url !== 'vulnDB') {
      html += `<span><a href="${escHtml(v.issue_url)}" target="_blank" rel="noopener">Issue Report &rarr;</a></span>`;
    }
    html += '</div>';

    // Description only (no separate analysis section)
    if (v.description) {
      html += `<div class="vuln-description">${escHtml(v.description)}</div>`;
    }

    // Code snippets (always visible, like RANsacked)
    if (v.code_snippets && v.code_snippets.length > 0) {
      html += '<div class="vuln-code">';
      html += '<div class="vuln-code-heading">Vulnerable Source Code</div>';
      v.code_snippets.forEach(s => {
        const lang = mapLang(s.lang);
        html += `<pre><code class="language-${lang}">${escHtml(s.code)}</code></pre>`;
      });
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  /* ===== Bibtex copy ===== */
  const BIBTEX = `@article{lin2026understanding,
  title={Understanding Implicit Trust Errors in Core Carrier Networks through Multi-Agent Flaw Discovery and Analysis},
  author={Lin, Ziyu and Wang, Ziting and Li, Xinfeng and Dong, Wei and Wang, XiaoFeng},
  journal={arXiv preprint arXiv:2607.10315},
  year={2026}
}`;
  const bibtexBtn = document.getElementById('bibtex-copy');
  if (bibtexBtn) {
    const bibtexLabel = bibtexBtn.querySelector('span');
    bibtexBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(BIBTEX).then(() => {
        bibtexLabel.textContent = 'Copied!';
        setTimeout(() => { bibtexLabel.textContent = 'Bibtex'; }, 1500);
      });
    });
  }

  /* ===== Helpers ===== */
  function groupByVendorProtocol(items) {
    const grouped = {};
    items.forEach(v => {
      if (!grouped[v.vendor]) grouped[v.vendor] = {};
      if (!grouped[v.vendor][v.protocol]) grouped[v.vendor][v.protocol] = [];
      grouped[v.vendor][v.protocol].push(v);
    });
    // Emit vendor groups in the canonical metadata.vendors order.
    const ordered = {};
    metadata.vendors.forEach(vd => { if (grouped[vd]) ordered[vd] = grouped[vd]; });
    Object.keys(grouped).forEach(vd => { if (!ordered[vd]) ordered[vd] = grouped[vd]; });
    return ordered;
  }

  function mapLang(lang) {
    const map = { cpp: 'cpp', c: 'c', go: 'go', text: 'plaintext' };
    return map[lang] || lang || 'plaintext';
  }

  function escHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function stripTags(html) {
    return html.replace(/<[^>]*>/g, '');
  }
})();
