export const jwtPattern = 'eyJ[A-Za-z0-9_-]{7,}(?:\\.[A-Za-z0-9_-]+){2,4}';
// PatternLayout covers message + throwable rendering. The global filter also protects JSON appenders.
export function redactLogConfig(xml) {
  if (xml.includes('copilot-jwt-redaction-v2')) return xml;
  xml = xml.replace(/<RegexReplacement\b[^>]*\/>/g,'')
    .replace(/<!-- copilot-jwt-redaction:[\s\S]*?-->\s*<RegexFilter\b[^>]*\/>/g,'');
  const replacement = `<replace regex="${jwtPattern}" replacement="[REDACTED_JWT]"/>`;
  const expanded = xml.replace(/<PatternLayout\b([^>]*?)\/>/g,`<PatternLayout$1>${replacement}</PatternLayout>`)
    .replace(/<PatternLayout\b([^>]*?)>([\s\S]*?)<\/PatternLayout>/g,(match,attrs,body) =>
      body.includes('<replace ') ? match : `<PatternLayout${attrs}>${replacement}${body}</PatternLayout>`);
  if (!expanded.includes(replacement) || !expanded.includes('<Appenders>')) throw Error('Unrecognized PF logging configuration');
  return expanded.replace('<Appenders>',`<!-- copilot-jwt-redaction-v2: suppress credential-bearing events, retain OAuth audit events -->\n<RegexFilter regex="(?s).*${jwtPattern}.*" useRawMsg="false" onMatch="DENY" onMismatch="NEUTRAL"/>\n<Appenders>`);
}
