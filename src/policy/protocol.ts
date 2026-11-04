import { createHash } from 'node:crypto';
export const bodyHash=(raw:string)=>createHash('sha256').update(raw).digest('base64url');
