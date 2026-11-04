// Isolated container integration profile. All principals below are synthetic test identities.
export const profile = Object.freeze({ human: 'partner-a:user-123', agent: 'partner-a:agent-research', org: 'partner-a', grant: 'grant-container',
  scope: 'copilot.invoke', agentIssuer: 'https://partner-a.test/agents', humanIssuer: 'https://partner-a.test/humans', delegationIssuer: 'https://partner-a.test/delegation', consentAuthorityIssuer:'https://partner-a.test/consent-authority' });
export const tokenType = 'urn:ietf:params:oauth:token-type:access_token';
export const attributes = ['actor_sub','actor_iss','org_id','delegation_id','execution_mode','scope'];
const fields = object => Object.entries(object).map(([name, value]) => ({ name, value: String(value) }));
const from = (type, value) => ({ source: { type }, value });
const condition = (type, attributeName, value) => ({ source: { type }, attributeName, condition: 'EQUALS', value });

export function processor(id, issuer, audience, jwks, extra = []) {
  return { id, name: id, pluginDescriptorRef: { id: 'com.pingidentity.pf.tokenprocessors.jwt.JwtTokenProcessor' },
    configuration: { fields: fields({ 'Require Audience': true, 'Require Expiration Time': true, 'Require Issued At Time': true, 'Require Not Before Time': true, 'Allowed Clock Skew': 5, 'Max Future Validity': 5 }),
      tables: [{ name: 'Allowed Issuers', rows: [{ fields: fields({ Issuer: issuer, JWKS: JSON.stringify(jwks) }) }] },
        { name: 'Allowed Audiences', rows: [{ fields: fields({ Audience: audience }) }] }] },
    attributeContract: { coreAttributes: [{ name: 'sub' }], extendedAttributes: [...new Set([...attributes, 'iss', ...extra])].map(name => ({ name })) } };
}
export function client(id, policy, atm, jwks) {
  return { clientId: id, name: id, enabled: true, clientAuth: { type: 'PRIVATE_KEY_JWT', enforceReplayPrevention: true, tokenEndpointAuthSigningAlgorithm: 'RS256' }, jwksSettings: { jwks: JSON.stringify(jwks) },
    grantTypes: ['TOKEN_EXCHANGE'], restrictScopes: true, restrictedScopes: [profile.scope],
    defaultAccessTokenManagerRef: { id: atm }, restrictToDefaultAccessTokenManager: true, tokenExchangeProcessorPolicyRef: { id: policy } };
}
export function tokenManager(node, issuer, audience) {
  const kid = `copilot-${node}-signing`;
  return { id: `copilot${node.toUpperCase()}JWT`, name: `Copilot ${node} signed test tokens`,
    pluginDescriptorRef: { id: 'com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin' },
    configuration: { fields: fields({ 'Token Lifetime': node === 'a' ? '3' : '1', 'JWS Algorithm': 'RS256',
      'Active Signing Certificate Key ID': kid, 'JWT ID Claim Length': '22', 'Issuer Claim Value': issuer, 'Audience Claim Value': audience,
      'Publish Keys to the PingFederate JWKS Endpoint': true, 'Not Before Claim Offset': '0', 'Include Issued At Claim': true, 'Type Header Value': 'at+jwt' }),
      tables: [{ name: 'Certificates', rows: [{ fields: fields({ 'Key ID': kid, Certificate: kid }) }] }] },
    attributeContract: { extendedAttributes: ['sub','act',...attributes.filter(a => a !== 'scope')].map(name => ({ name })) },
    selectionSettings: { resourceUris: [audience] },
    accessControlSettings: { restrictClients: true, allowedClients: [{ id: node === 'a' ? 'gateway-1-token-exchange' : 'gateway-2-token-exchange' }] } };
}
export function exchangePolicy(node) {
  const mappings = node === 'a'
    ? [{ type: 'urn:example:token-type:interactive-proof', processor: 'copilotHuman', mode: 'interactive' }, { type: 'urn:example:token-type:delegation-proof', processor: 'copilotDelegation', mode: 'autonomous' }]
    : [{ type: tokenType, processor: 'copilotUpstream' }];
  return { id: `copilot${node.toUpperCase()}Policy`, name: `Copilot ${node} subject and actor policy`, actorTokenRequired: node === 'a',
    attributeContract: { coreAttributes: [{ name: 'subject' }], extendedAttributes: attributes.filter(a => a !== 'scope').map(name => ({ name })) },
    processorMappings: mappings.map(({ type, processor: id, mode }) => ({
      subjectTokenType: type, subjectTokenProcessor: { id },
      ...(node === 'a' ? { actorTokenType: 'urn:example:token-type:agent-proof', actorTokenProcessor: { id: 'copilotAgent' } } : {}),
      attributeContractFulfillment: { subject: from('SUBJECT_TOKEN','sub'),
        actor_sub: from(node === 'a' ? 'ACTOR_TOKEN' : 'SUBJECT_TOKEN', node === 'a' ? 'sub' : 'actor_sub'),
        actor_iss: from(node === 'a' ? 'ACTOR_TOKEN' : 'SUBJECT_TOKEN', node === 'a' ? 'iss' : 'actor_iss'),
        ...Object.fromEntries(['org_id','delegation_id','execution_mode'].map(a => [a, from('SUBJECT_TOKEN',a)])) },
      issuanceCriteria: { conditionalCriteria: [
        condition('SUBJECT_TOKEN','sub',profile.human), condition('SUBJECT_TOKEN','org_id',profile.org),
        condition('SUBJECT_TOKEN','delegation_id',profile.grant), condition('SUBJECT_TOKEN','scope',profile.scope),
        condition('SUBJECT_TOKEN','actor_sub',profile.agent), condition('SUBJECT_TOKEN','actor_iss',profile.agentIssuer),
        ...(mode ? [condition('SUBJECT_TOKEN','execution_mode',mode)] : []),
        ...(node === 'a' ? [condition('ACTOR_TOKEN','sub',profile.agent), condition('ACTOR_TOKEN','iss',profile.agentIssuer)] : []),
      ] },
    })) };
}
export function accessTokenMapping(node) {
  return { context: { type: 'TOKEN_EXCHANGE_PROCESSOR_POLICY', contextRef: { id: `copilot${node.toUpperCase()}Policy` } }, accessTokenManagerRef: { id: `copilot${node.toUpperCase()}JWT` },
    attributeContractFulfillment: { sub: from('TOKEN_EXCHANGE_PROCESSOR_POLICY','subject'),
      ...Object.fromEntries(attributes.filter(a => a !== 'scope').map(a => [a, from('TOKEN_EXCHANGE_PROCESSOR_POLICY',a)])),
      act: from('EXPRESSION', '#m=new java.util.LinkedHashMap(), #m.put("sub",#this.get("tepp.actor_sub").toString()), #m.put("iss",#this.get("tepp.actor_iss").toString()), #m'),
    } };
}
