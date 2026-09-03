export interface OrgBranding {
  accent?: string;
  mark?: string;
  selfLabel?: string;
  preset?: BrandPreset;
}

export type BrandPreset = "risely";

export function brandPreset(value: unknown): BrandPreset | undefined {
  return value === "risely" ? value : undefined;
}

export function brandAccent(preset: BrandPreset | undefined): string | undefined {
  return preset === "risely" ? "#5533E2" : undefined;
}

export function brandLogoSvg(preset: BrandPreset | undefined): string {
  if (preset !== "risely") return "";
  return `<svg class="brand-logo" width="49" height="48" viewBox="0 0 49 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><rect x="0.25" width="48" height="48" rx="12" fill="url(#risely-brand-bg)"/><path d="M18.1746 18.3541H22.1289C25.5999 12.5952 31.0042 12.3754 34.2556 12.9909C34.7828 13.0788 35.1782 13.4744 35.2661 14.002C35.8812 17.2551 35.6615 22.6623 29.9058 26.1352V30.0917C29.9058 31.1907 29.2907 32.2457 28.324 32.8172L24.4576 35.1032C24.1061 35.2791 23.7106 35.323 23.4031 35.1032C23.0516 34.9274 22.8758 34.5757 22.8758 34.18V29.1685C22.8758 28.1574 22.4804 27.1902 21.7774 26.4869C21.0744 25.7835 20.1078 25.3878 19.0973 25.3878H14.0884C13.693 25.3878 13.3415 25.212 13.1657 24.8603C12.9461 24.5526 12.9461 24.1569 13.1657 23.8052L15.4505 19.9367C16.0217 18.9695 17.0761 18.3541 18.1746 18.3541ZM29.9058 16.5957C28.8952 16.5957 28.1483 17.387 28.1483 18.3541C28.1483 19.3652 28.8952 20.1125 29.9058 20.1125C30.8724 20.1125 31.6633 19.3652 31.6633 18.3541C31.6633 17.387 30.8724 16.5957 29.9058 16.5957Z" fill="white"/><path d="M20.328 33.3886C18.1751 35.5866 13.0345 35.2349 13.0345 35.2349C13.0345 35.2349 12.683 30.0915 14.8359 27.9374C16.3737 26.4427 18.8342 26.4427 20.328 27.9374C21.8219 29.4321 21.8219 31.8939 20.328 33.3886ZM18.263 30.0036C17.7797 29.476 16.9449 29.476 16.4616 30.0036C15.7146 30.7069 15.8465 32.4214 15.8465 32.4214C15.8465 32.4214 17.56 32.5533 18.263 31.806C18.7902 31.3224 18.7902 30.4871 18.263 30.0036Z" fill="url(#risely-brand-accent)"/><defs><linearGradient id="risely-brand-bg" x1="46.823" y1="2.83764e-06" x2="2.19791" y2="46.3463" gradientUnits="userSpaceOnUse"><stop stop-color="#5533E2" stop-opacity="0.909804"/><stop offset="0.782165" stop-color="#2F1E7F"/></linearGradient><linearGradient id="risely-brand-accent" x1="20.1517" y1="28.024" x2="13.0309" y2="34.6684" gradientUnits="userSpaceOnUse"><stop offset="0.112544" stop-color="#FF707E"/><stop offset="0.949303" stop-color="#FFA3AC"/></linearGradient></defs></svg>`;
}

const REFRESH_MS = 30_000;
const RETRY_MS = 5_000;
const FIRST_RENDER_WAIT_MS = 1_500;

export interface BrandingCache {
  current(): OrgBranding;
  forRender(): Promise<OrgBranding>;
  refreshNow(): Promise<void>;
}

export function createBrandingCache(fetchBranding: () => Promise<OrgBranding>): BrandingCache {
  let value: OrgBranding = {};
  let warmed = false;
  let nextAt = 0;
  let inflight: Promise<void> | null = null;

  const kick = (): void => {
    if (inflight || Date.now() < nextAt) return;
    inflight = (async () => {
      try {
        value = await fetchBranding();
        if (process.env.BRANDING_DEBUG) console.error("[branding] fetched:", JSON.stringify(value));
        warmed = true;
        nextAt = Date.now() + REFRESH_MS;
      } catch (err) {
        if (process.env.BRANDING_DEBUG) console.error("[branding] fetch failed:", String(err));
        nextAt = Date.now() + RETRY_MS;
      } finally {
        inflight = null;
      }
    })();
  };
  setTimeout(kick, 0);

  return {
    current: () => value,
    async forRender(): Promise<OrgBranding> {
      kick();
      if (!warmed && inflight) {
        await Promise.race([inflight, new Promise((r) => setTimeout(r, FIRST_RENDER_WAIT_MS))]);
      }
      return value;
    },
    async refreshNow(): Promise<void> {
      if (inflight) await inflight;
      nextAt = 0;
      kick();
      if (inflight) await inflight;
    },
  };
}

const escapeAttr = (v: string): string =>
  v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function injectBranding(html: string, branding: OrgBranding, opts?: { titleSuffix?: string }): string {
  const { selfLabel } = branding;
  const preset = brandPreset(branding.preset);
  const accent = /^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(branding.accent ?? "")
    ? branding.accent
    : brandAccent(preset);
  const mark = (branding.mark ?? "").replace(/["\\\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 2) || undefined;
  let out = html;
  if (selfLabel) {
    out = out.replace(
      /(<meta name="brand-self-label" content=")[^"]*(")/,
      (_m, pre: string, post: string) => `${pre}${escapeAttr(selfLabel)}${post}`,
    );
    if (opts?.titleSuffix) {
      const title = escapeAttr(`${selfLabel} ${opts.titleSuffix}`);
      out = out.replace(/<title>[^<]*<\/title>/, () => `<title>${title}</title>`);
    }
  }
  if (preset) {
    out = out.replace(/<html(\s|>)/, (_m, tail: string) => `<html data-brand-preset="${preset}"${tail}`);
    out = out.replace(
      /(<meta name="brand-preset" content=")[^"]*(")/,
      (_m, pre: string, post: string) => `${pre}${preset}${post}`,
    );
    out = out.replace(/<span class="brand-mark" data-brand-logo aria-hidden="true"><\/span\s*>/, brandLogoSvg(preset));
  }
  const decls = [...(accent ? [`--brand-accent:${accent}`] : []), ...(mark ? [`--brand-mark:"${mark}"`] : [])].join(
    ";",
  );
  if (decls) out = out.replace("</head>", () => `<style>:root{${decls}}</style></head>`);
  return out;
}
