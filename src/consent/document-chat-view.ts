const escape=(v:string)=>v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
// Presentation only. The owning controller must enforce signed-in identity,
// distinct chat/document consent, CSRF, durable allowances and cleanup.
export function documentChatView(input:{csrf:string;ready:boolean;answer?:{answer:string;source:{name:string}}}){
 if(!/^[A-Za-z0-9_-]{43}$/.test(input.csrf))throw Error('document_chat_view_configuration');
 const body=input.answer?`<section aria-label="Copilot answer"><h2>Copilot answer</h2><p style="white-space:pre-wrap">${escape(input.answer.answer)}</p><p>Approved source: ${escape(input.answer.source.name)}</p><small>This is model output; verify it against the source.</small></section>`:input.ready?`<p>Ask one question about the approved synthetic SharePoint sample. Your question and that document will be sent to Copilot Studio.</p><form method="post" action="/check"><input type="hidden" name="csrf" value="${input.csrf}"><label for="question">Your question</label><textarea id="question" name="question" maxlength="2000" required></textarea><button type="submit">Ask Copilot</button></form>`:'<p>Complete sign-in and the separate chat and document approvals before asking a question.</p>';
 return`<section aria-label="Document chat"><h1>Ask about the approved document</h1>${body}<p>Access is limited to the approved sample. Text in a document cannot grant permissions or select another site.</p></section>`;
}
