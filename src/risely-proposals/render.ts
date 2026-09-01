import { canonicalJson } from "../cron/schedule-authority.ts";
import type { RiselyProposalInput } from "./contracts.ts";

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const LINE_HEIGHT = 14;
const PAGE_LINES = 47;

function cleanPdfText(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[^\x20-\x7e]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function wrap(value: string, width = 82): string[] {
  const lines: string[] = [];
  for (const paragraph of value.split(/\r?\n/)) {
    const words = paragraph.trim().split(/\s+/).filter(Boolean);
    if (!words.length) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      if (word.length > width) {
        if (line) lines.push(line);
        for (let offset = 0; offset < word.length; offset += width) lines.push(word.slice(offset, offset + width));
        line = "";
        continue;
      }
      const next = line ? `${line} ${word}` : word;
      if (next.length > width) {
        lines.push(line);
        line = word;
      } else line = next;
    }
    if (line) lines.push(line);
  }
  return lines;
}

function proposalLines(input: Readonly<RiselyProposalInput>): string[] {
  const lines = [
    input.title,
    `Prepared for ${input.client}`,
    `Revision ${input.revision} | Valid until ${input.validUntil.slice(0, 10)}`,
    "",
  ];
  for (const section of input.sections) {
    lines.push(
      section.heading.toUpperCase(),
      ...wrap(section.content),
      `Evidence: ${section.evidenceRefs.join(", ")}`,
      "",
    );
  }
  lines.push("EVIDENCE REGISTER");
  for (const item of input.evidence) {
    lines.push(...wrap(`[${item.id}] ${item.source} ${item.recordRef} ${item.revision}`));
    lines.push(...wrap(`${item.summary} | ${item.citation}`), "");
  }
  lines.push("PRIVATE DRAFT", "Release eligible: no", "External publication requires a separate exact QM approval.");
  return lines;
}

function pdfObject(value: string): Buffer {
  return Buffer.from(value, "ascii");
}

export function renderProposalPdf(input: Readonly<RiselyProposalInput>): Buffer {
  const all = proposalLines(input);
  const pages: string[][] = [];
  for (let offset = 0; offset < all.length; offset += PAGE_LINES) pages.push(all.slice(offset, offset + PAGE_LINES));
  const objects: Buffer[] = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects.push(pdfObject("<< /Type /Catalog /Pages 2 0 R >>"));
  objects.push(
    pdfObject(`<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`),
  );
  objects.push(pdfObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"));
  for (const [index, lines] of pages.entries()) {
    const pageId = pageIds[index]!;
    const contentId = pageId + 1;
    objects.push(
      pdfObject(
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`,
      ),
    );
    const operators = ["BT", "/F1 10 Tf", `50 ${PAGE_HEIGHT - 54} Td`, `${LINE_HEIGHT} TL`];
    for (const line of lines) operators.push(`(${cleanPdfText(line)}) Tj`, "T*");
    operators.push("ET");
    const stream = pdfObject(operators.join("\n"));
    objects.push(
      Buffer.concat([pdfObject(`<< /Length ${stream.byteLength} >>\nstream\n`), stream, pdfObject("\nendstream")]),
    );
  }
  const chunks = [pdfObject("%PDF-1.4\n%QMPR\n")];
  const offsets = [0];
  let length = chunks[0]!.byteLength;
  for (const [index, object] of objects.entries()) {
    offsets.push(length);
    const chunk = Buffer.concat([pdfObject(`${index + 1} 0 obj\n`), object, pdfObject("\nendobj\n")]);
    chunks.push(chunk);
    length += chunk.byteLength;
  }
  const xref = length;
  const trailer = [
    `xref\n0 ${objects.length + 1}`,
    "0000000000 65535 f ",
    ...offsets.slice(1).map((offset) => `${String(offset).padStart(10, "0")} 00000 n `),
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>`,
    `startxref\n${xref}`,
    "%%EOF\n",
  ].join("\n");
  chunks.push(pdfObject(trailer));
  return Buffer.concat(chunks);
}

function html(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function renderProposalHtml(input: Readonly<RiselyProposalInput>): Buffer {
  const sections = input.sections
    .map(
      (section) =>
        `<section><h2>${html(section.heading)}</h2><p>${html(section.content).replace(/\n/g, "<br>")}</p><small>Evidence: ${html(section.evidenceRefs.join(", "))}</small></section>`,
    )
    .join("");
  const evidence = input.evidence
    .map(
      (item) =>
        `<li id="${html(item.id)}"><strong>${html(item.source)}</strong> ${html(item.recordRef)} ${html(item.revision)}<br>${html(item.summary)}<br><span>${html(item.citation)}</span></li>`,
    )
    .join("");
  return Buffer.from(
    `<!doctype html><html><head><meta charset="utf-8"><title>${html(input.title)}</title><style>body{font:16px system-ui;line-height:1.55;max-width:850px;margin:48px auto;padding:0 24px;color:#17202a}h1,h2{color:#102a43}section{margin:36px 0}small,footer{color:#52606d}li{margin:18px 0}.private{border:1px solid #cbd5e1;padding:16px;background:#f8fafc}</style></head><body><header><h1>${html(input.title)}</h1><p>Prepared for ${html(input.client)}</p><p>Revision ${input.revision} · Valid until ${html(input.validUntil.slice(0, 10))}</p></header>${sections}<section><h2>Evidence register</h2><ol>${evidence}</ol></section><footer class="private"><strong>Private draft</strong><br>Release eligible: no. External publication requires a separate exact QM approval.</footer></body></html>`,
    "utf8",
  );
}

export function renderEvidenceManifest(input: Readonly<RiselyProposalInput>): Buffer {
  return Buffer.from(
    canonicalJson({
      contract: 1,
      proposalId: input.proposalId,
      revision: input.revision,
      releaseEligible: false,
      evidence: input.evidence,
      sectionBindings: input.sections.map(({ key, evidenceRefs }) => ({ key, evidenceRefs })),
    }),
    "utf8",
  );
}

export function renderEmailDraft(input: Readonly<RiselyProposalInput>): Buffer {
  const draft = input.emailDraft ?? {
    to: "To be confirmed",
    subject: `${input.title} — private draft`,
    body: `Please find the private proposal draft for ${input.client}. No email has been sent.`,
  };
  return Buffer.from(
    canonicalJson({ contract: 1, disposition: "draft_only", releaseEligible: false, sendEligible: false, ...draft }),
    "utf8",
  );
}
