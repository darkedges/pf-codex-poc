const absent = response => response.status === 400 &&
  response.value?.errors?.some(error => typeof error === 'string' && /invalid accessor/i.test(error));

export async function retireRuntimeLease(request, token, accessor) {
  const options = { method: 'POST', token, body: { accessor } };
  const retired = await request('/auth/token/revoke-accessor', options);
  if (retired.status === 204 || absent(retired)) return;
  // Some Vault versions return 200 for an already expired accessor. Confirm
  // absence independently before issuing a replacement workload credential.
  if (retired.status === 200 && absent(await request('/auth/token/lookup-accessor', options))) return;
  throw Error('Previous runtime lease could not be retired');
}
