import { ProvisioningError } from './power-platform.ts';

// PAC 2.14.1 emits zero bytes for an empty admin list in JSON mode.
// Require an independent, exact English text confirmation before accepting [].
export function confirmEmptyPacList(value:string):unknown[]{
 const lines=value.replace(/^\uFEFF/,'').split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
 if(lines.length!==4||!/^Connected as [A-Za-z0-9._+@-]{3,254}$/.test(lines[0])||lines[1]!=='Listing all environments from your tenant...'||lines[2]!=='Listing environment groups from your tenant...'||lines[3]!=='No environments were found in your tenant.')throw new ProvisioningError('response_invalid');
 return [];
}
