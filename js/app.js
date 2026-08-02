/* 5GC-Vuln-Atlas — rendering + filtering */
(function () {
  'use strict';

  const { metadata, vulnerabilities } = VULN_DATA;

  /* ===== DOM refs (must be before any function that uses them) ===== */
  const filterVendor = document.getElementById('filter-vendor');
  const filterProtocol = document.getElementById('filter-protocol');
  const filterPattern = document.getElementById('filter-pattern');
  const filterSearch = document.getElementById('filter-search');
  const filterReset = document.getElementById('filter-reset');

  /* ===== Hero Stats ===== */
  document.getElementById('stat-total').textContent = metadata.total;
  document.getElementById('stat-vendors').textContent = 7;
  document.getElementById('stat-protocols').textContent = metadata.protocols.length;
  const cveCount = vulnerabilities.filter(v => v.cve).length;
  document.getElementById('stat-cves').textContent = cveCount;

  /* ===== Cross Table ===== */
  buildCrossTable();

  /* ===== Bar Charts ===== */
  buildBarCharts();

  /* ===== Populate Filters ===== */
  populateFilters();

  /* ===== Render Vuln List ===== */
  renderAll();

  /* ===== Filter Events ===== */
  [filterVendor, filterProtocol, filterPattern].forEach(el =>
    el.addEventListener('change', renderAll)
  );
  filterSearch.addEventListener('input', debounce(renderAll, 200));
  filterReset.addEventListener('click', () => {
    filterVendor.value = '';
    filterProtocol.value = '';
    filterPattern.value = '';
    filterSearch.value = '';
    renderAll();
  });

  /* Deep-link: jump to anchor on load */
  if (location.hash) {
    setTimeout(() => {
      const el = document.getElementById(location.hash.slice(1));
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);
  }

  /* ================================================================ */

  function getFiltered() {
    const v = filterVendor.value;
    const pr = filterProtocol.value;
    const pa = filterPattern.value;
    const q = filterSearch.value.trim().toLowerCase();

    return vulnerabilities.filter(item => {
      if (v && item.vendor !== v) return false;
      if (pr && item.protocol !== pr) return false;
      if (pa && item.pattern !== pa) return false;
      if (q) {
        const haystack = [
          item.id, item.title, item.cve || '', item.cwe || '',
          item.description, item.crash_type, item.target,
          item.vendor_display, item.protocol_display, item.pattern,
          item.pattern_display,
        ].join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }

  function renderAll() {
    const filtered = getFiltered();
    document.getElementById('filter-count').textContent = filtered.length;
    document.getElementById('filter-total').textContent = metadata.total;
    renderVulnList(filtered);
    renderTOC(filtered);
  }

  /* ===== Cross Table ===== */
  function buildCrossTable() {
    const table = document.getElementById('cross-table');
    const patterns = metadata.patterns;
    const vendors = metadata.vendors;

    const counts = {};
    vendors.forEach(v => {
      counts[v] = {};
      patterns.forEach(p => { counts[v][p] = 0; });
    });
    vulnerabilities.forEach(item => {
      if (counts[item.vendor] && counts[item.vendor][item.pattern] !== undefined) {
        counts[item.vendor][item.pattern]++;
      }
    });

    let html = '<thead><tr><th>Vendor</th>';
    patterns.forEach(p => { html += `<th>${metadata.pattern_display[p]}</th>`; });
    html += '<th>Total</th></tr></thead><tbody>';

    vendors.forEach(v => {
      html += `<tr><td>${metadata.vendor_display[v]}</td>`;
      let rowTotal = 0;
      patterns.forEach(p => {
        const n = counts[v][p];
        rowTotal += n;
        html += `<td class="num ${n === 0 ? 'num-zero' : ''}">${n}</td>`;
      });
      html += `<td class="num">${rowTotal}</td></tr>`;
    });

    html += '<tr><td><strong>Total</strong></td>';
    let grandTotal = 0;
    patterns.forEach(p => {
      const colSum = vendors.reduce((s, v) => s + counts[v][p], 0);
      grandTotal += colSum;
      html += `<td class="num">${colSum}</td>`;
    });
    html += `<td class="num">${grandTotal}</td></tr>`;
    html += '</tbody>';

    table.innerHTML = html;
  }

  /* ===== Bar Charts ===== */
  function buildBarCharts() {
    const vendorCounts = {};
    metadata.vendors.forEach(v => { vendorCounts[v] = 0; });
    vulnerabilities.forEach(item => { vendorCounts[item.vendor]++; });
    const maxVendor = Math.max(...Object.values(vendorCounts));
    document.getElementById('chart-vendor').innerHTML = metadata.vendors.map(v => {
      const n = vendorCounts[v];
      const pct = (n / maxVendor * 100).toFixed(0);
      return `<div class="bar-row">
        <span class="bar-label">${metadata.vendor_display[v]}</span>
        <span class="bar-track"><span class="bar-fill vendor" style="width:${pct}%"></span></span>
        <span class="bar-value">${n}</span>
      </div>`;
    }).join('');

    const patternCounts = {};
    metadata.patterns.forEach(p => { patternCounts[p] = 0; });
    vulnerabilities.forEach(item => { patternCounts[item.pattern]++; });
    const maxPattern = Math.max(...Object.values(patternCounts));
    document.getElementById('chart-pattern').innerHTML = metadata.patterns.map(p => {
      const n = patternCounts[p];
      const pct = (n / maxPattern * 100).toFixed(0);
      return `<div class="bar-row">
        <span class="bar-label">${metadata.pattern_display[p]}</span>
        <span class="bar-track"><span class="bar-fill pattern-${p}" style="width:${pct}%"></span></span>
        <span class="bar-value">${n}</span>
      </div>`;
    }).join('');

    const protoCounts = {};
    metadata.protocols.forEach(p => { protoCounts[p] = 0; });
    vulnerabilities.forEach(item => { protoCounts[item.protocol]++; });
    const maxProto = Math.max(...Object.values(protoCounts));
    document.getElementById('chart-protocol').innerHTML = metadata.protocols.map(p => {
      const n = protoCounts[p];
      const pct = (n / maxProto * 100).toFixed(0);
      return `<div class="bar-row">
        <span class="bar-label">${metadata.protocol_display[p]}</span>
        <span class="bar-track"><span class="bar-fill protocol" style="width:${pct}%"></span></span>
        <span class="bar-value">${n}</span>
      </div>`;
    }).join('');
  }

  /* ===== Populate Filters ===== */
  function populateFilters() {
    metadata.vendors.forEach(v => {
      const opt = document.createElement('option');
      opt.value = v;
      opt.textContent = metadata.vendor_display[v];
      filterVendor.appendChild(opt);
    });
    metadata.protocols.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = metadata.protocol_display[p];
      filterProtocol.appendChild(opt);
    });
    metadata.patterns.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = metadata.pattern_display[p];
      filterPattern.appendChild(opt);
    });
  }

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

    if (filtered.length === 0) {
      container.innerHTML = '<div class="no-results">No vulnerabilities match the current filters.</div>';
      return;
    }

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

  function debounce(fn, ms) {
    let timer;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
  }
})();
