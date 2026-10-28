import { AuthError } from './jwt.ts';
export type Mode = 'interactive'|'autonomous';
export type Grant = {id:string; user:string; agent:string; org:string; status:'active'|'revoked'; modes:Mode[]; scopes:string[]; resources:string[]; expires:string};
// Demo fixture. Production: persistent, authenticated policy service with real revocation and lifecycle events.
export const grants: Record<string,Grant> = {
  'grant-demo': {id:'grant-demo',user:'partner-a:user-123',agent:'partner-a:agent-research',org:'partner-a',status:'active',modes:['interactive','autonomous'],scopes:['copilot.invoke','m365.document.read','enterprise.customer.read'],resources:['sharepoint:approved-research','enterprise:customer-123'],expires:'2030-01-01T00:00:00Z'},
  'grant-revoked': {id:'grant-revoked',user:'partner-a:user-123',agent:'partner-a:agent-research',org:'partner-a',status:'revoked',modes:['interactive','autonomous'],scopes:['copilot.invoke','m365.document.read'],resources:['sharepoint:approved-research'],expires:'2030-01-01T00:00:00Z'}
};
export function grantFor(id: string): Grant {const g=grants[id]; if (!g) throw new AuthError('Unknown grant'); return g;}
export function authorise(input: {grantId:string; user:string; agent:string; mode:Mode; scope:string; resource:string}): Grant {
  const g=grantFor(input.grantId);
  if(g.status!=='active' || Date.parse(g.expires) <= Date.now()) throw new AuthError('Grant revoked or expired');
  if(g.user!==input.user || g.agent!==input.agent) throw new AuthError('Subject/actor not covered by grant');
  if(!g.modes.includes(input.mode)) throw new AuthError('Mode not delegated');
  if(!g.scopes.includes(input.scope) || !g.resources.includes(input.resource)) throw new AuthError('Operation/resource not delegated');
  return g;
}
export function operationScope(operation:string,resource:string): string {
  if(operation==='documents.search' && resource==='sharepoint:approved-research') return 'm365.document.read';
  if(operation==='customer.read' && resource==='enterprise:customer-123') return 'enterprise.customer.read';
  throw new AuthError('Unsupported operation or resource');
}
