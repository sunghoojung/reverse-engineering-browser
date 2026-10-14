// Optional offline Python-only project. Native Go/JavaScript export is unchanged.
import {readFile} from 'node:fs/promises';
import client from '../apps/research-ui/captured_client.js';

export async function pythonProject(source, mode, httpClient) {
  const versions = {requests:'2.34.2',httpx:'0.28.1'};
  if (!Object.hasOwn(versions,httpClient)) throw new TypeError('Choose requests or httpx.');
  const project = client.capturedClientProject(source,mode);
  const prefix = 'reb-client-project/';
  const paths = ['provenance.json','requests/request-001.json','config.example.json','.gitignore','evidence/capture.json','evidence/repeater-run.json'];
  const files = project.files.filter(file=>paths.includes(file.path.slice(prefix.length)));
  const add = (path,text) => files.push({path:prefix+path,text});
  files.find(file=>file.path===prefix+'.gitignore').text+='__pycache__/\n.venv/\n';
  const config = files.find(file=>file.path===prefix+'config.example.json');
  const settings = JSON.parse(config.text);settings.configVersion='reb-python-client-config-v1';
  config.text=JSON.stringify(settings,null,2)+'\n';
  // Keep the shared evidence/privacy warnings, but describe this archive's transport.
  project.provenance.limitations=project.provenance.limitations.map(value =>
    value.startsWith('Default Go uses ') ? 'Python uses standard '+httpClient+' with certificate verification and per-operation timeouts, not an overall deadline. No browser profile, ambient proxy, cookie carryover or automatic decompression.' :
    value.startsWith('Both clients omit ') ? 'This Python client omits browser credentials and stops redirects; optional response checks must be configured explicitly.' : value);
  project.provenance.client_capabilities={language:'python',http_client:httpClient,dependency_version:versions[httpClient],
    timeout_scope:'per-operation',overall_deadline:false,redirect_following:false,ambient_proxy:false,cookies:'omit',browser_profile:false};
  files.find(file=>file.path===prefix+'provenance.json').text=JSON.stringify(project.provenance,null,2)+'\n';
  const template = await readFile(new URL('./templates/captured_client_python.py',import.meta.url),'utf8');
  add('client.py',template.replace('__REB_PYTHON_CLIENT__',httpClient).replace('__REB_PYTHON_VERSION__',versions[httpClient]));
  add('requirements.txt',httpClient+'=='+versions[httpClient]+'\n');
  add('README.md',`# One observed Python request

This offline project uses ${httpClient} ${versions[httpClient]} with Python 3.11+. Captured inputs are JSON data, never executable source. The export is one observed operation, not an inferred service API or verified replay.

## Review and run

Review requirements.txt, then install it explicitly into your own virtual environment with python -m pip install -r requirements.txt. Export never installs dependencies. The client requires this exact provider version before sending. The direct dependency is pinned; its transitive dependency resolution is not a complete lockfile. Follow your environment's dependency review policy.

Run python client.py for a dry run with zero target requests; dry runs need only the standard library, not the provider dependency. Copy config.example.json to config.json, review the request/evidence and set allowedOrigin to the exact authorized origin. Only python client.py --send performs one deliberate request. No automatic retry occurs. Both clients verify TLS certificates, refuse ambient TLS key logging, ignore ambient proxy/netrc configuration, omit original browser cookies, and do not follow redirects or automatically decompress response bodies.

## Python timeout contract

configVersion is reb-python-client-config-v1. timeoutMs (or request.timeout_ms when null) is 100–30000 ms per blocking operation. Requests has separate connect/read timeouts; HTTPX also applies write/pool timeouts. This is NOT an overall deadline: DNS resolution, multiple address attempts, and a response that keeps producing bytes can take longer. The provenance records this capability. Existing Go/JavaScript reb-client-config-v1 files are rejected instead of silently weakening their whole-request deadline.

The remaining request, origin, redirectPolicy, cookiePolicy, standard transport and opt-in responseChecks fields have the existing meanings. An unsupported browser profile fails before sending. Redacted or unsupported captures require a complete reviewed config.request. Missing, null, wrong-type and unexpected JSON field values remain distinct. Numeric equality requires the original exact integer JSON token; duplicate keys and invalid Unicode fail.

## Bounds and limitations

Inputs/configuration are at most 1 MiB and JSON depth 64. Request text is at most 64 KiB; headers at most 64 pairs/16 KiB. Python requires ASCII URLs and header values. Preparation that changes the captured URL path/query is rejected; supply a deliberately reviewed URL rather than assuming equivalence. Encoded query spellings may therefore require manual reconstruction, especially with Requests. Multipart, binary, truncated and credential-bearing inputs remain evidence, not runnable defaults. Responses retain at most 64 KiB body and 128 headers/64 KiB header text. Configured checks cannot pass truncated responses.

Header casing/order, automatic headers, TLS, compression, CORS and browser state differ. Neither provider implements the optional Go browser-profile adapter or browser fingerprint parity. Error reports preserve an unknown server outcome after an attempted send; inspect state before another deliberate request. There is no response persistence, streaming API or login/credential acquisition.

Export mode: ${mode}. Raw evidence may contain credentials or personal data. The explicit best-effort redacted copy can still contain sensitive names, paths and identifiers. Review before sharing. .gitignore is not a security boundary. Source provenance describes a saved snapshot and does not attest to authenticity or current retention.
`);
  return {files,provenance:project.provenance,bytes:client.capturedClientZip(files)};
}
