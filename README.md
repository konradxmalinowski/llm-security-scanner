# llm-security-scanner — GitHub Pages site

This branch is the static source for the marketing/docs site served at
https://konradxmalinowski.github.io/llm-security-scanner/. It is **not**
the project's source code. For the actual Python CLI, switch to the
main branch (`main`).

## No build step

This branch contains plain static HTML/CSS/JS — there is no generator,
no bundler, and no templating step. Jekyll processing is explicitly
disabled via the root `.nojekyll` file, so GitHub Pages serves these
files exactly as committed, with no processing in between.

## File layout

- `index.html` — landing page
- `docs/<slug>/index.html` — docs pages, one folder per topic, each with
  its own `index.html`. Current slugs: `getting-started`,
  `cli-reference`, `output-formats`, `owasp-coverage`, `security`,
  `cicd`
- `static/` — shared assets: `theme.css`, `app.js`, `favicon.svg`,
  `og-image.png`
- `robots.txt`
- `sitemap.xml`
- `404.html`

## Local preview

No install or build step is needed. From the branch root:

```bash
python3 -m http.server
```

Then open the printed `localhost` URL in a browser.

## Publishing

Changes are committed and pushed directly to `gh-pages` — there is no
PR/merge process and no CI build step for this branch. A push goes
live on the Pages site immediately.

## Keeping docs in sync

The pages under `docs/` are static HTML conversions of the CLI's
documentation. They must be kept in sync manually with the CLI's
actual flags and behavior as documented on `main` — nothing automates
that sync.
