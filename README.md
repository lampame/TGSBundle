# [![Build GramJS Bundle](https://github.com/lampame/TGSBundle/actions/workflows/build.yml/badge.svg)](https://github.com/lampame/TGSBundle/actions/workflows/build.yml)

Auto-built browser bundle of [GramJS](https://github.com/gram-js/gramjs) for use in plugins via CDN.

## Usage

```html
<script src="https://cdn.jsdelivr.net/gh/lampame/TGSBundle@main/telegram.min.js"></script>
<script>
  const client = new window.telegram.TelegramClient(
    window.telegram.Api,
    session,
    apiId,
    apiHash,
    { connectionRetries: 5 }
  );
</script>
```

## Versioning

Pin a specific tag instead of `@main` to avoid unexpected changes caused by the jsDelivr cache (up to 7 days):

```html
<script src="https://cdn.jsdelivr.net/gh/lampame/TGSBundle@v1.2.3/telegram.min.js"></script>
```

The `v1.2.3` tag should match the corresponding GramJS release.

## How It Works

A GitHub Actions workflow runs daily at 03:00 UTC — it clones the GramJS repository, builds it with webpack, minifies with terser, and commits the result back to this repo.

To trigger a build manually, go to the **Actions** tab → **Build GramJS Bundle** → **Run workflow**.

## Files

| File | Description |
|------|-------------|
| `telegram.js` | Full bundle (~828 KB) |
| `telegram.min.js` | Minified bundle |

## Links

- [GramJS](https://github.com/gram-js/gramjs) — the original library
- [jsDelivr](https://www.jsdelivr.com/) — CDN for GitHub
