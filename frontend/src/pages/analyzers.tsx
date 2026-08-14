/**
 * The five submission routes.
 *
 * Each supplies its copy, examples and a light client-side validator to the
 * shared form. The validators intentionally mirror -- not replace -- the
 * backend's Pydantic rules; they exist to give instant feedback on typos.
 */

import { FileUploadForm, TextIndicatorForm } from '../components/AnalyzeForms';
import { api } from '../services/api';

function CheckList({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2 text-xs leading-relaxed text-content-secondary">
      {items.map((item) => (
        <li key={item} className="flex gap-2">
          <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" aria-hidden />
          {item}
        </li>
      ))}
    </ul>
  );
}

/* -------------------------------------------------------------------------- */

export function AnalyzeUrl() {
  return (
    <TextIndicatorForm
      title="URL analysis"
      description="Static inspection of the URL's structure. The link is parsed, never requested."
      label="URL"
      placeholder="https://example.com/path"
      examples={[
        'https://example.com/products/overview',
        'http://secure-login.paypal.account-verify.example/session/renew',
        'https://cdn-update-service.example/downloads/invoice.pdf.exe',
        'http://198.51.100.23:8081/gate.php?id=8837',
      ]}
      steps={[
        'Parsing URL structure and validating syntax',
        'Classifying host and extracting the registrable domain',
        'Evaluating structural and encoding heuristics',
        'Querying threat-intelligence providers',
      ]}
      helper={
        <CheckList
          items={[
            'Syntax validity, scheme and transport encryption',
            'IP-literal hosts, punycode and excessive subdomain depth',
            'Brand names in subdomains and credential-themed keywords',
            'Embedded credentials, nested URLs and heavy percent-encoding',
            'Directly linked executables and double file extensions',
            'High-abuse TLDs and URL shortening services',
          ]}
        />
      }
      validate={(value) => {
        if (!value) return 'Enter a URL to analyse.';
        if (value.length > 2048) return 'URLs longer than 2048 characters are not supported.';
        if (/\s/.test(value)) return 'A URL cannot contain spaces.';
        return null;
      }}
      submit={(value) => api.analyzeUrl(value)}
    />
  );
}

/* -------------------------------------------------------------------------- */

export function AnalyzeHash() {
  return (
    <TextIndicatorForm
      title="Hash analysis"
      description="Identifies the digest algorithm and queries every enabled threat-intelligence provider."
      label="File hash"
      placeholder="MD5, SHA-1 or SHA-256 digest"
      examples={[
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        '44d88612fea8a8f36de82e1278abb02f',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      ]}
      steps={[
        'Validating digest format',
        'Identifying the hash algorithm from its length',
        'Querying threat-intelligence providers',
      ]}
      helper={
        <>
          <CheckList
            items={[
              'Algorithm identification: MD5 (32), SHA-1 (40), SHA-256 (64 hex characters)',
              'Collision-resistance caveats for MD5 and SHA-1',
              'Recognition of well-known digests such as the empty file',
              'Reputation lookup across every enabled provider',
            ]}
          />
          <p className="mt-4 border-t border-border-subtle pt-3 text-xs leading-relaxed text-content-muted">
            The first example is the SHA-256 of the EICAR anti-malware test file — a harmless,
            industry-standard artefact published so detection pipelines can be verified safely.
          </p>
        </>
      }
      validate={(value) => {
        if (!value) return 'Enter a file hash to analyse.';
        if (!/^[a-fA-F0-9]+$/.test(value)) {
          return 'A hash contains hexadecimal characters only (0-9, a-f).';
        }
        if (![32, 40, 64].includes(value.length)) {
          return `That is ${value.length} characters. Expected 32 (MD5), 40 (SHA-1) or 64 (SHA-256).`;
        }
        return null;
      }}
      submit={(value) => api.analyzeHash(value)}
    />
  );
}

/* -------------------------------------------------------------------------- */

export function AnalyzeIp() {
  return (
    <TextIndicatorForm
      title="IP address analysis"
      description="Classifies the address against the IANA special-purpose registries. No packets are sent to it."
      label="IP address"
      placeholder="IPv4 or IPv6 address"
      examples={['8.8.8.8', '203.0.113.66', '198.51.100.23', '2001:db8::1']}
      steps={[
        'Validating address syntax',
        'Classifying scope against IANA registries',
        'Performing a reverse (PTR) lookup where enabled',
        'Querying threat-intelligence providers',
      ]}
      helper={
        <>
          <CheckList
            items={[
              'IPv4 and IPv6 syntax validation',
              'Scope classification: public, private, loopback, link-local, multicast, documentation',
              'IPv4-mapped IPv6 and Teredo tunnelling detection',
              'Reverse DNS, including hosting-provider identification',
              'Reputation lookup across every enabled provider',
            ]}
          />
          <p className="mt-4 border-t border-border-subtle pt-3 text-xs leading-relaxed text-content-muted">
            No connection is ever made to the address. There is no ping, no port scan and no traffic
            of any kind directed at the submitted host.
          </p>
        </>
      }
      validate={(value) => {
        if (!value) return 'Enter an IP address to analyse.';
        if (/^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+$/.test(value)) {
          return 'That looks like a domain name. Use the Domain tab instead.';
        }
        if (!/^[0-9a-fA-F.:[\]]+$/.test(value)) return 'That is not a valid IPv4 or IPv6 address.';
        return null;
      }}
      submit={(value) => api.analyzeIp(value)}
    />
  );
}

/* -------------------------------------------------------------------------- */

export function AnalyzeDomain() {
  return (
    <TextIndicatorForm
      title="Domain analysis"
      description="Structural heuristics plus optional passive DNS. No connection is made to the domain's services."
      label="Domain name"
      placeholder="example.com"
      examples={[
        'example.org',
        'secure-login-verify.example',
        'a7f3k9x2m8q4v1z6.cdn-update-service.example',
        'paypal.secure.attacker-domain.example',
      ]}
      steps={[
        'Validating hostname syntax',
        'Extracting the registrable domain and subdomain labels',
        'Evaluating structural and entropy heuristics',
        'Resolving A/AAAA records where enabled',
      ]}
      helper={
        <CheckList
          items={[
            'RFC 1123 hostname syntax validation',
            'Registrable domain and subdomain decomposition',
            'Punycode detection with the rendered Unicode form',
            'Shannon entropy on the second-level label to spot DGA-like names',
            'Brand impersonation, credential keywords and high-abuse TLDs',
            'Passive A/AAAA resolution when DNS lookups are enabled',
          ]}
        />
      }
      validate={(value) => {
        if (!value) return 'Enter a domain name to analyse.';
        if (value.includes('/') || value.includes('://')) {
          return 'Enter a bare domain without a scheme or path. Use the URL tab for full links.';
        }
        if (value.includes(':')) return 'Remove the port number — enter the domain only.';
        if (!value.includes('.'))
          return 'A domain must include a top-level domain, e.g. example.com.';
        return null;
      }}
      submit={(value) => api.analyzeDomain(value)}
    />
  );
}

/* -------------------------------------------------------------------------- */

export function AnalyzeFile() {
  return <FileUploadForm />;
}
