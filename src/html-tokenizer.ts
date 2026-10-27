export interface HtmlToken {
  readonly type: "start" | "end" | "text";
  readonly name?: string;
  readonly attributes?: ReadonlyMap<string, string>;
  readonly text?: string;
}

export interface HtmlTokenization {
  readonly tokens: readonly HtmlToken[];
  readonly truncated: boolean;
}

const RAW_TEXT_ELEMENTS = new Set(["script", "style", "textarea", "title", "iframe", "noembed", "noframes", "noscript", "xmp", "plaintext"]);
const MAX_INPUT_CHARS = 5_000_000;
const MAX_TOKENS = 40_000;
const MAX_ATTRIBUTES_PER_ELEMENT = 128;
const MAX_ATTRIBUTE_VALUE_CHARS = 4096;

function tagNameCharacter(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 45 || code === 58;
}

function attributeNameCharacter(code: number): boolean {
  return code > 32 && code !== 34 && code !== 39 && code !== 47 && code !== 60 && code !== 61 && code !== 62;
}

function findTagEnd(html: string, start: number): number {
  let quote = 0;
  for (let index = start; index < html.length; index += 1) {
    const code = html.charCodeAt(index);
    if (quote !== 0) {
      if (code === quote) quote = 0;
      continue;
    }
    if (code === 34 || code === 39) quote = code;
    else if (code === 62) return index;
  }
  return -1;
}

function findRawTextClosingTag(lower: string, elementName: string, start: number): number {
  const marker = `</${elementName}`;
  let candidate = lower.indexOf(marker, start);
  while (candidate >= 0) {
    const delimiter = lower.charCodeAt(candidate + marker.length);
    if (delimiter === 62 || delimiter === 47 || delimiter <= 32) return candidate;
    candidate = lower.indexOf(marker, candidate + marker.length);
  }
  return -1;
}

function entityCodePoint(value: string): string {
  const entity = value.slice(1, -1);
  if (entity === "amp") return "&";
  if (entity === "lt") return "<";
  if (entity === "gt") return ">";
  if (entity === "quot") return "\"";
  if (entity === "apos") return "'";
  if (entity === "nbsp") return "\u00a0";
  const numeric = entity[0]?.toLowerCase() === "#";
  if (!numeric) return value;
  const codePoint = entity[1]?.toLowerCase() === "x"
    ? Number.parseInt(entity.slice(2), 16)
    : Number.parseInt(entity.slice(1), 10);
  if (!Number.isInteger(codePoint) || codePoint <= 0 || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) return "\uFFFD";
  return String.fromCodePoint(codePoint);
}

export function decodeHtmlEntities(value: string): string {
  return value.replace(/&(?:amp|lt|gt|quot|apos|nbsp|#\d{1,8}|#x[\da-f]{1,6});/gi, entityCodePoint);
}

/**
 * A bounded linear tokenizer for the small HTML subset RevenueGuard inspects.
 * It skips comments and raw script/style text, parses exact attribute names,
 * and never builds a DOM from untrusted response content.
 */
export function tokenizeHtml(input: string): HtmlTokenization {
  const html = input.slice(0, MAX_INPUT_CHARS);
  const lower = html.toLowerCase();
  const tokens: HtmlToken[] = [];
  let cursor = 0;
  let rawTextElement: string | undefined;
  let truncated = input.length > MAX_INPUT_CHARS;

  while (cursor < html.length) {
    if (tokens.length >= MAX_TOKENS) {
      truncated = true;
      break;
    }

    if (rawTextElement) {
      if (rawTextElement === "plaintext") break;
      const closeStart = findRawTextClosingTag(lower, rawTextElement, cursor);
      if (closeStart < 0) break;
      if ((rawTextElement === "title" || rawTextElement === "textarea") && closeStart > cursor) {
        tokens.push({ type: "text", text: html.slice(cursor, closeStart).slice(0, 8192) });
      }
      cursor = closeStart;
      rawTextElement = undefined;
    }

    const open = html.indexOf("<", cursor);
    if (open < 0) break;
    if (open > cursor) {
      const text = html.slice(cursor, open);
      if (text.length) tokens.push({ type: "text", text: text.slice(0, 8192) });
      cursor = open;
      if (tokens.length >= MAX_TOKENS) { truncated = true; break; }
    }

    if (html.startsWith("<!--", cursor)) {
      const commentEnd = html.indexOf("-->", cursor + 4);
      if (commentEnd < 0) break;
      cursor = commentEnd + 3;
      continue;
    }

    const next = html.charCodeAt(cursor + 1);
    if (next === 33 || next === 63) {
      const declarationEnd = findTagEnd(html, cursor + 2);
      if (declarationEnd < 0) break;
      cursor = declarationEnd + 1;
      continue;
    }

    let index = cursor + 1;
    let closing = false;
    if (html.charCodeAt(index) === 47) { closing = true; index += 1; }
    while (index < html.length && html.charCodeAt(index) <= 32) index += 1;
    const nameStart = index;
    while (index < html.length && tagNameCharacter(html.charCodeAt(index))) index += 1;
    if (index === nameStart) { cursor += 1; continue; }
    const name = lower.slice(nameStart, index);
    const end = findTagEnd(html, index);
    if (end < 0) break;

    if (closing) {
      tokens.push({ type: "end", name });
      cursor = end + 1;
      continue;
    }

    const attributes = new Map<string, string>();
    let attributeCount = 0;
    while (index < end && attributeCount < MAX_ATTRIBUTES_PER_ELEMENT) {
      while (index < end && (html.charCodeAt(index) <= 32 || html.charCodeAt(index) === 47)) index += 1;
      if (index >= end) break;
      const attrStart = index;
      while (index < end && attributeNameCharacter(html.charCodeAt(index))) index += 1;
      if (index === attrStart) { index += 1; continue; }
      const attrName = lower.slice(attrStart, index);
      attributeCount += 1;
      while (index < end && html.charCodeAt(index) <= 32) index += 1;
      let value = "";
      if (html.charCodeAt(index) === 61) {
        index += 1;
        while (index < end && html.charCodeAt(index) <= 32) index += 1;
        const quote = html.charCodeAt(index);
        let valueStart: number;
        if (quote === 34 || quote === 39) {
          index += 1;
          valueStart = index;
          while (index < end && html.charCodeAt(index) !== quote) index += 1;
          value = html.slice(valueStart, index).slice(0, MAX_ATTRIBUTE_VALUE_CHARS);
          if (html.charCodeAt(index) === quote) index += 1;
        } else {
          valueStart = index;
          while (index < end && html.charCodeAt(index) > 32 && html.charCodeAt(index) !== 62) index += 1;
          value = html.slice(valueStart, index).slice(0, MAX_ATTRIBUTE_VALUE_CHARS);
        }
      }
      if (!attributes.has(attrName)) attributes.set(attrName, decodeHtmlEntities(value));
    }

    tokens.push({ type: "start", name, attributes });
    cursor = end + 1;
    // HTML ignores a self-closing slash on non-void elements such as script/style.
    if (RAW_TEXT_ELEMENTS.has(name)) rawTextElement = name;
  }

  return { tokens, truncated };
}
