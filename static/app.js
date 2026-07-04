  function copyCode(btn) {
    const block = btn.closest('.code-block');
    const pre = block.querySelector('pre');
    const text = pre.textContent || pre.innerText;
    navigator.clipboard.writeText(text.trim()).then(() => {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 1800);
    }).catch(() => {
      const range = document.createRange();
      range.selectNodeContents(pre);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    });
  }

  function initScenarioSwitchers(root = document) {
    root.querySelectorAll('[data-scenario-switcher]').forEach((switcher) => {
      const buttons = Array.from(switcher.querySelectorAll('button[data-scenario-target]'));
      const scope = switcher.closest('.scenario-card, [data-scenario-scope]') || root;
      const panels = Array.from(scope.querySelectorAll('[data-scenario-panel]'));

      buttons.forEach((button) => {
        button.addEventListener('click', () => {
          const target = button.dataset.scenarioTarget;
          buttons.forEach((item) => item.classList.toggle('active', item === button));
          panels.forEach((panel) => {
            panel.classList.toggle('active', panel.dataset.scenarioPanel === target);
          });
        });
      });
    });
  }

  initScenarioSwitchers();

  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        navLinks.forEach(link => {
          link.style.color = '';
          if (link.getAttribute('href') === '#' + entry.target.id) {
            if (!link.classList.contains('nav-cta')) {
              link.style.color = 'var(--text)';
            }
          }
        });
      }
    });
  }, { rootMargin: '-40% 0px -55% 0px' });

  sections.forEach(s => observer.observe(s));

  // ── Docs: mark the active sidebar link based on the current path ──
  document.querySelectorAll('.docs-nav-group a').forEach((link) => {
    if (link.getAttribute('href') === window.location.pathname) {
      link.classList.add('active');
    }
  });

  // ── Docs: simple client-side filter for the sidebar search box ──
  const docsSearchInput = document.getElementById('docs-search-input');
  if (docsSearchInput) {
    docsSearchInput.addEventListener('input', () => {
      const query = docsSearchInput.value.trim().toLowerCase();
      document.querySelectorAll('.docs-nav-group').forEach((group) => {
        let groupHasMatch = false;
        group.querySelectorAll('li').forEach((item) => {
          const link = item.querySelector('a');
          const keywords = link ? (link.dataset.kw || '') : '';
          const haystack = (item.textContent + ' ' + keywords).toLowerCase();
          const matches = haystack.includes(query);
          item.style.display = matches ? '' : 'none';
          if (matches) groupHasMatch = true;
        });
        group.style.display = groupHasMatch ? '' : 'none';
      });
    });
  }

  // ── Landing docs router: load docs into the workspace without leaving the page ──
  // GitHub Pages serves this as a project page under /llm-security-scanner/, not
  // at the domain root, so every path comparison below must account for that
  // base prefix instead of assuming '/' and '/docs' are the real root paths.
  const SITE_BASE = '/llm-security-scanner';
  const HOME_PATH = SITE_BASE + '/';
  const DOCS_BASE = SITE_BASE + '/docs';
  function isDocsPath(pathname) {
    return pathname === DOCS_BASE || pathname.startsWith(DOCS_BASE + '/');
  }

  const appWorkspace = document.getElementById('app-workspace');
  if (appWorkspace) {
    const landingShell = document.createElement('div');
    landingShell.id = 'landing-shell';
    landingShell.className = 'landing-shell';
    while (appWorkspace.firstChild) {
      landingShell.appendChild(appWorkspace.firstChild);
    }
    appWorkspace.appendChild(landingShell);

    let docsPanel = null;
    let activeDocsPath = null;
    let docsRequestId = 0;

    function showLanding() {
      activeDocsPath = null;
      docsRequestId += 1;
      landingShell.hidden = false;
      if (docsPanel) {
        docsPanel.hidden = true;
      }
      document.body.classList.remove('docs-view');
    }

    function showDocsPanel() {
      landingShell.hidden = true;
      const panel = ensureDocsPanel();
      panel.hidden = false;
      document.body.classList.add('docs-view');
      return panel;
    }

    function setActiveDocsLink(pathname) {
      const normalizedPath = pathname || HOME_PATH;
      const onDocsPath = isDocsPath(normalizedPath);
      document.querySelectorAll('.nav-submenu a, .topbar-nav a').forEach((link) => {
        const href = link.getAttribute('href');
        const linkPath = href ? new URL(href, window.location.origin).pathname : '';
        const shouldBeActive = onDocsPath && linkPath === normalizedPath;
        link.classList.toggle('active', shouldBeActive);
      });
      if (isDocsPath(window.location.pathname)) {
        document
          .querySelectorAll(`.topbar-nav a[href="${DOCS_BASE}/"], .nav-submenu a[href="${DOCS_BASE}/"]`)
          .forEach((link) => {
            link.classList.add('active');
          });
      }
    }

    function ensureDocsPanel() {
      if (!docsPanel) {
        docsPanel = document.createElement('section');
        docsPanel.className = 'docs-content docs-content-embedded';
        appWorkspace.appendChild(docsPanel);
      }
      return docsPanel;
    }

    async function loadDocs(pathname, options = {}) {
      const url = new URL(pathname, window.location.origin);
      if (!isDocsPath(url.pathname)) return false;

      const { pushState = true } = options;
      const requestId = ++docsRequestId;
      if (activeDocsPath === url.pathname && docsPanel) {
        if (url.hash) {
          const target = docsPanel.querySelector(url.hash);
          if (target) {
            target.scrollIntoView({ block: 'start', behavior: 'auto' });
          } else {
            docsPanel.scrollIntoView({ block: 'start', behavior: 'auto' });
          }
        } else {
          docsPanel.scrollIntoView({ block: 'start', behavior: 'auto' });
        }
        return true;
      }

      const panel = showDocsPanel();
      setActiveDocsLink(url.pathname);

      try {
        const response = await fetch(url.pathname + url.search, { credentials: 'same-origin' });
        if (!response.ok) throw new Error(`Docs request failed with ${response.status}`);
        const html = await response.text();
        if (requestId !== docsRequestId) return false;
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const source = doc.querySelector('.docs-content');
        if (!source) throw new Error('Docs content container not found');

        if (requestId !== docsRequestId) return false;
        panel.innerHTML = source.innerHTML;
        activeDocsPath = url.pathname;
        setActiveDocsLink(url.pathname);
        initScenarioSwitchers(panel);

        if (pushState) {
          history.pushState({ view: 'docs', path: url.pathname + url.search + url.hash }, '', url.pathname + url.search + url.hash);
        }

        if (url.hash) {
          requestAnimationFrame(() => {
            const target = panel.querySelector(url.hash);
            if (target) {
              target.scrollIntoView({ block: 'start', behavior: 'auto' });
            } else {
              panel.scrollIntoView({ block: 'start', behavior: 'auto' });
            }
          });
        } else {
          panel.scrollIntoView({ block: 'start', behavior: 'auto' });
        }
        return true;
      } catch (error) {
        window.location.href = url.pathname + url.search + url.hash;
        return false;
      }
    }

    function restoreLanding(options = {}) {
      const { pushState = false, hash = '' } = options;
      showLanding();
      if (pushState) {
        history.pushState({ view: 'landing' }, '', hash ? `${HOME_PATH}${hash}` : HOME_PATH);
      }
      setActiveDocsLink(window.location.pathname);
      if (hash) {
        requestAnimationFrame(() => {
          const target = document.querySelector(hash);
          if (target) target.scrollIntoView({ block: 'start', behavior: 'auto' });
        });
      }
    }

    function handleLinkClick(event) {
      const link = event.target.closest('a[href]');
      if (!link || link.target === '_blank' || link.hasAttribute('download')) return;

      const href = link.getAttribute('href');
      if (!href) return;

      const isHashOnly = href.startsWith('#');
      const isRootHash = href.startsWith(`${HOME_PATH}#`);
      if (docsPanel && (isHashOnly || isRootHash)) {
        event.preventDefault();
        restoreLanding({
          pushState: true,
          hash: isHashOnly ? href : href.slice(HOME_PATH.length),
        });
        return;
      }

      const url = new URL(href, window.location.href);
      if (url.origin !== window.location.origin) return;

      const onDocsPath = isDocsPath(url.pathname);
      const isHomePath = url.pathname === HOME_PATH || url.pathname === SITE_BASE;

      if (onDocsPath) {
        event.preventDefault();
        loadDocs(url.pathname + url.search + url.hash, { pushState: true });
        return;
      }

      if (docsPanel && isHomePath) {
        event.preventDefault();
        restoreLanding({ pushState: true, hash: url.hash });
      }
    }

    document.addEventListener('click', handleLinkClick);

    window.addEventListener('popstate', () => {
      if (isDocsPath(window.location.pathname)) {
        loadDocs(window.location.pathname + window.location.search + window.location.hash, {
          pushState: false,
        });
      } else {
        showLanding();
        setActiveDocsLink(window.location.pathname);
      }
    });

    if (isDocsPath(window.location.pathname)) {
      loadDocs(window.location.pathname + window.location.search + window.location.hash, {
        pushState: false,
      });
    } else {
      showLanding();
      setActiveDocsLink(window.location.pathname);
    }
  }
