import { buildLegacySlackCard, buildPrivateCeoSurface, buildSlackCardFromSurface } from "../presentation/index.mjs";

const SlackLimits = Object.freeze({
  blocks: 50,
  fallback: 4000,
  header: 150,
  section: 3000,
  field: 2000,
  context: 3000,
  contextElements: 10,
});

function normalized(value) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/gu, " ");
}

function compact(value, maximum) {
  const result = normalized(value);
  return result.length <= maximum ? result : `${result.slice(0, Math.max(0, maximum - 1)).trimEnd()}…`;
}

function escapedPart(character) {
  if (character === "&") return "&amp;";
  if (character === "<") return "&lt;";
  if (character === ">") return "&gt;";
  return character;
}

function boundedMrkdwn(value, maximum) {
  const text = normalized(value);
  let escaped = "";
  for (const character of text) escaped += escapedPart(character);
  if (escaped.length <= maximum) return escaped;
  let shortened = "";
  for (const character of text) {
    const part = escapedPart(character);
    if (shortened.length + part.length > maximum - 1) break;
    shortened += part;
  }
  return `${shortened.trimEnd()}…`;
}

function plain(value, maximum) {
  return Object.freeze({ type: "plain_text", text: compact(value, maximum), emoji: true });
}

function markdown(value, maximum) {
  return Object.freeze({ type: "mrkdwn", text: boundedMrkdwn(value, maximum) });
}

function evidenceLabel(evidence) {
  if (!evidence.length) return "Evidence: none attached";
  const unavailable = evidence.filter((item) => item.availability === "unavailable").length;
  return unavailable
    ? `Evidence: ${evidence.length - unavailable} available · ${unavailable} unavailable`
    : `Evidence: ${evidence.length} source records`;
}

function stableLinkElement(link) {
  if (!link.url) return markdown(`Linked workspace: ${link.label}`, SlackLimits.context);
  const text = `<${link.url}|${boundedMrkdwn(link.label, 70)}>`;
  return text.length <= SlackLimits.context
    ? Object.freeze({ type: "mrkdwn", text })
    : markdown("Authenticated QM workspace", SlackLimits.context);
}

function evidenceBlocks(evidence) {
  if (!evidence.length) {
    return [
      Object.freeze({
        type: "section",
        text: markdown("*Evidence*\nNo evidence record is attached.", SlackLimits.section),
      }),
    ];
  }
  return evidence.map((item, index) =>
    Object.freeze({
      type: "section",
      text: markdown(
        `*Evidence ${index + 1} · ${item.evidenceRef}*\n${item.trust} · ${item.availability}`,
        SlackLimits.section,
      ),
    }),
  );
}

function renderCard(card, links = []) {
  const blocks = [
    Object.freeze({ type: "header", text: plain("Risely CEO Agent", SlackLimits.header) }),
    Object.freeze({
      type: "section",
      text: markdown(
        `*${card.status.label} · ${card.artifact.kindLabel}*\n${card.artifact.title}\n${card.artifact.summary}`,
        SlackLimits.section,
      ),
    }),
    Object.freeze({
      type: "context",
      elements: Object.freeze([
        markdown("Private CEO review", 80),
        markdown(`Artifact ${card.artifact.artifactRef}`, 300),
        markdown(`Revision ${card.artifact.revision}`, 80),
        markdown(`Status ${card.status.state}`, 80),
        markdown(evidenceLabel(card.evidence), 120),
        markdown("Actionless preview · no external action can run", 180),
      ]),
    }),
    ...evidenceBlocks(card.evidence),
  ];
  if (links.length) {
    blocks.push(
      Object.freeze({
        type: "context",
        elements: Object.freeze(links.slice(0, SlackLimits.contextElements).map(stableLinkElement)),
      }),
    );
  }
  if (blocks.length > SlackLimits.blocks) throw new RangeError("Slack block limit exceeded");
  return Object.freeze({
    response_type: "ephemeral",
    text: compact(card.fallbackText, SlackLimits.fallback),
    blocks: Object.freeze(blocks),
  });
}

export function renderPrivateCeoSlackBlockKitFromSurface(snapshot) {
  return renderCard(buildSlackCardFromSurface(snapshot));
}

export function renderPrivateCeoSlackBlockKit(input) {
  return renderPrivateCeoSlackBlockKitFromSurface(buildPrivateCeoSurface(input));
}

export function renderSlackBlockKit(input) {
  const card = buildLegacySlackCard(input);
  return renderCard(card, card.links);
}

export { SlackLimits };
