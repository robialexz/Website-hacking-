import assert from "node:assert/strict";
import { test } from "node:test";

import { tokenizeHtml } from "./html-tokenizer.ts";

test("parses exact attributes and decodes common and numeric entities", () => {
  const parsed = tokenizeHtml('<a href="/about?a=1&amp;b=2" hrefx="/wrong" data-x=&#x41;>About</a>');
  const anchor = parsed.tokens.find((token) => token.type === "start" && token.name === "a");
  assert.equal(anchor?.attributes?.get("href"), "/about?a=1&b=2");
  assert.equal(anchor?.attributes?.get("hrefx"), "/wrong");
  assert.equal(anchor?.attributes?.get("data-x"), "A");
});

test("does not interpret comments or script/style contents as HTML", () => {
  const parsed = tokenizeHtml(`<!-- <a href="/comment"> -->
    <script>const fake = '</scriptish><a href="/script">';</script>
    <script/>const stillFake = '<a href="/self-closed-script">';</script>
    <style>.x::after { content: "<a href='/style'>" }</style>
    <iframe><a href="/iframe-fallback">Fallback</a></iframe>
    <a href="/real">Real</a>`);
  const links = parsed.tokens.filter((token) => token.type === "start" && token.name === "a")
    .map((token) => token.attributes?.get("href"));
  assert.deepEqual(links, ["/real"]);
});

test("captures title text and bounds tokenization for oversized hostile HTML", () => {
  const title = tokenizeHtml("<title>Safe &amp; Sound</title>");
  assert.deepEqual(title.tokens.filter((token) => token.type === "text").map((token) => token.text), ["Safe &amp; Sound"]);

  const oversized = tokenizeHtml("<a>".repeat(50_000));
  assert.equal(oversized.truncated, true);
  assert.ok(oversized.tokens.length <= 40_000);
});
