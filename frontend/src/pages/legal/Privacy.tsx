/**
 * Privacy policy.
 *
 * Written against the code rather than from a template. Two disclosures in
 * particular exist because the implementation makes them true and a generic
 * policy would have missed both:
 *
 *   - deleting an uploaded file's bytes is not the same as deleting what was
 *     read out of it (see clause 4 — sample strings and embedded indicators
 *     are persisted in the report);
 *   - clearing browser storage orphans a workspace rather than erasing it
 *     (clause 8), which is the opposite of what a visitor would assume.
 */

import LegalPage, {
  Bullet,
  Bullets,
  Callout,
  FactTable,
  Mono,
  P,
  Term,
  type Clause,
} from './LegalPage';
import { CONTACT_EMAIL, JURISDICTION, OPERATOR, SUPERVISORY_AUTHORITY } from './legalMeta';

const CLAUSES: Clause[] = [
  {
    id: 'scope',
    title: 'Who this covers',
    body: (
      <>
        <P>
          This policy describes how the SentinelCTI web application handles information when you use
          it. {OPERATOR} operates this instance and is the data controller for it.
        </P>
        <P>
          SentinelCTI is open-source software that anyone may deploy. This policy describes{' '}
          <Term>this deployment only</Term>. A different operator running the same code makes their
          own choices about hosting, retention and configuration, and is responsible for their own
          instance.
        </P>
        <P>
          There are no user accounts. Nothing here asks for your name, email address, telephone
          number or payment details, and there is nothing to register for.
        </P>
      </>
    ),
  },
  {
    id: 'submissions',
    title: 'What you submit, and what that means',
    body: (
      <>
        <P>
          The service exists to analyse indicators you give it: a URL, a domain, an IP address, a
          file hash, or an uploaded file. Submitting one is a deliberate act, and the analysis is
          stored so you can return to the report.
        </P>
        <Callout tone="warning">
          <Term>Do not submit confidential, personal or regulated data.</Term> This is a
          demonstration platform, not an accredited analysis service. Indicators frequently carry
          personal data without the sender noticing — a URL with a session token or an email address
          in its query string, a filename containing someone's name, a document whose text includes
          contact details. Treat anything you submit as retained and readable by whoever administers
          this instance.
        </Callout>
      </>
    ),
  },
  {
    id: 'stored',
    title: 'What is stored',
    body: (
      <>
        <P>
          One record is written per analysis. It contains the submission and everything the analysis
          derived from it:
        </P>
        <FactTable
          rows={[
            {
              id: 'indicator',
              label: 'The indicator',
              value:
                'The submitted value, normalised. For a file submission this is the sanitised filename — not the file itself.',
            },
            {
              id: 'result',
              label: 'The result',
              value:
                'Risk score, verdict, status, every named finding with its points and rationale, any MITRE ATT&CK associations, how long the analysis took, and a timestamp.',
            },
            {
              id: 'details',
              label: 'Technical details',
              value:
                'Whatever the analyzer observed: for a URL, its decomposed parts; for a domain, entropy and suffix data; for a file, its hashes, size, magic-byte type and entropy.',
            },
            {
              id: 'strings',
              label: 'Text read out of uploaded files',
              value: (
                <>
                  Up to 60 sample strings extracted from the file, plus the URLs, IP addresses, email
                  addresses and file paths found inside it. See clause 4 — this is the part people do
                  not expect.
                </>
              ),
            },
            {
              id: 'providers',
              label: 'Provider results',
              value:
                'What each configured threat-intelligence provider returned. On the default configuration that is an offline engine which contacts nothing.',
            },
            {
              id: 'workspace-key',
              label: 'A workspace key',
              value: (
                <>
                  A random value your browser generates, stored against the record so the service can
                  show you your own history. See clause 7.
                </>
              ),
            },
          ]}
        />
        <P>
          <Term>What is not stored:</Term> no account data, because there are no accounts; no
          passwords; no uploaded file contents (clause 4); and no IP addresses in the database
          (clause 5).
        </P>
      </>
    ),
  },
  {
    id: 'uploads',
    title: 'Uploaded files: the bytes go, the text stays',
    body: (
      <>
        <P>
          An uploaded file is written to a quarantine directory that sits outside every static mount,
          under a random name. No route in the API returns file bytes, so an upload is never
          web-reachable. After analysis the bytes are deleted — in a{' '}
          <Mono>finally</Mono> block, so deletion happens even when the analysis failed part way.
          Files are never executed, never extracted and never opened by a format library.
        </P>
        <Callout tone="warning">
          <Term>Deleting the file is not the same as deleting what was read out of it.</Term> The
          analysis extracts printable text, and up to 60 of those strings are kept in the stored
          report, along with any URLs, IP addresses, email addresses and file paths found inside. If
          you upload a document containing personal data, fragments of that data can persist in the
          report after the file itself is gone. Delete the report (clause 7) to remove them.
        </Callout>
        <P>
          Hashes of the file — MD5, SHA-1 and SHA-256 — are retained permanently as part of the
          report. A hash is not reversible into the file, but it does identify that exact file to
          anyone who already holds a copy.
        </P>
      </>
    ),
  },
  {
    id: 'ip-addresses',
    title: 'IP addresses and rate limiting',
    body: (
      <>
        <P>
          The application uses your IP address to enforce a request rate limit. It is held in memory
          only, as a short series of timestamps, and the structure is swept and capped so it does not
          grow without bound. It is <Term>not written to the database</Term> and is not associated
          with your submissions.
        </P>
        <P>
          Whoever hosts and fronts this deployment keeps their own request logs, which typically
          include IP addresses, and those are outside the application's control. See clause 9 for who
          those parties are.
        </P>
      </>
    ),
  },
  {
    id: 'browser-storage',
    title: 'Browser storage — and why there is no cookie banner',
    body: (
      <>
        <P>
          The site sets <Term>no cookies at all</Term>. It runs no analytics, no advertising, no
          tag manager, no session recording and no third-party scripts of any kind — the content
          security policy on this deployment blocks scripts, styles, fonts, images and network
          connections from any other origin. There is nothing to consent to, which is why you are not
          asked to.
        </P>
        <P>Two values are kept in your browser's own storage:</P>
        <FactTable
          rows={[
            {
              id: 'workspace-storage',
              label: <Mono>sentinelcti.workspace</Mono>,
              value: (
                <>
                  Local storage, persistent. 256 bits of randomness generated by your browser on
                  first visit, sent with each request as a header so the service can show you your own
                  analyses and not anyone else's. It identifies a browser, not a person, and is never
                  placed in a URL.
                </>
              ),
            },
            {
              id: 'token-storage',
              label: <Mono>sentinelcti.access_token</Mono>,
              value:
                'Session storage, and only on instances published behind an optional shared-token gate. It is discarded when the tab closes.',
            },
          ]}
        />
        <P>
          Neither is a cookie; neither is sent to any third party. Both are removed when you clear
          site data for this domain — but read clause 8 before you do, because for the workspace key
          that has a consequence.
        </P>
      </>
    ),
  },
  {
    id: 'workspace',
    title: 'What the workspace key is, and is not',
    body: (
      <>
        <P>
          The workspace key gives you a private view of your own submissions without an account. The
          server stamps it onto each analysis you create and filters every read by it.
        </P>
        <P>
          It is <Term>isolation, not authentication</Term>. Nothing proves you are the same person
          who created a workspace — only that your browser holds the key. Three consequences follow,
          and all three are deliberate trade-offs for having no login:
        </P>
        <Bullets>
          <Bullet>Anyone who obtains the key can see that workspace.</Bullet>
          <Bullet>
            A workspace belongs to a browser, not a person. The same person on a phone and a laptop
            has two, and they cannot be merged.
          </Bullet>
          <Bullet>
            If your browser blocks storage, no key is sent. The service still works; your submissions
            simply are not linked to you and cannot be listed later.
          </Bullet>
        </Bullets>
        <P>
          Analyses marked <Term>DEMO</Term> belong to no workspace and are visible to everyone. They
          are synthetic records produced by a seed script over reserved, non-routable test indicators
          — they contain nobody's data, and nobody can delete them.
        </P>
      </>
    ),
  },
  {
    id: 'retention',
    title: 'How long it is kept, and how to remove it',
    body: (
      <>
        <P>
          Analyses are retained <Term>until they are deleted</Term>. There is no automatic expiry.
          Uploaded file bytes are the exception: those are deleted immediately after analysis, every
          time.
        </P>
        <P>You can remove data yourself in two ways:</P>
        <Bullets>
          <Bullet>
            <Term>Delete a report.</Term> Open it and use “Delete report”. The record is removed from
            the database. This is the only action that erases stored data.
          </Bullet>
          <Bullet>
            <Term>Start a fresh workspace.</Term> Settings → Your data → “Start a new workspace”.
            Your browser takes a new key, and the console stops showing the old analyses.
          </Bullet>
        </Bullets>
        <Callout tone="warning">
          <Term>Starting a new workspace hides your history; it does not erase it.</Term> The same is
          true of clearing your browser's site data. The records stay in the database, but the key
          that reached them is gone — which means neither you nor anyone else can list them, and you
          can no longer delete them yourself. If you want data gone, delete the reports first, then
          reset. If you have already lost a key, clause 11 explains what can still be done.
        </Callout>
      </>
    ),
  },
  {
    id: 'recipients',
    title: 'Who else sees it',
    body: (
      <>
        <P>
          Nothing is sold, rented, shared for advertising, or used to build a profile of you. Data
          reaches these parties and no others:
        </P>
        <FactTable
          rows={[
            {
              id: 'hosting',
              label: 'Hosting provider',
              value:
                'Serves the application and runs the API. Handles all traffic and keeps its own request logs.',
            },
            {
              id: 'database',
              label: 'Database provider',
              value:
                'Stores the analysis records described in clause 3, in the region configured for the instance.',
            },
            {
              id: 'resolver',
              label: 'DNS resolver',
              value: (
                <>
                  When passive DNS lookups are enabled — they are on by default — the hostname you
                  submit is sent to the configured resolver so it can be resolved. The query goes to
                  that resolver, never to the indicator's own infrastructure. The Settings page shows
                  whether this is enabled here.
                </>
              ),
            },
            {
              id: 'intel-providers',
              label: 'Threat-intelligence providers',
              value: (
                <>
                  Only those configured on the instance, and only the indicator itself. The default
                  configuration uses an offline engine that contacts nothing, so by default no
                  indicator leaves this deployment. The Settings page lists the current roster.
                </>
              ),
            },
            {
              id: 'legal-disclosure',
              label: 'Legal disclosure',
              value:
                'Data may be disclosed where required by law, or to establish or defend a legal claim.',
            },
          ]}
        />
        <P>
          These providers process data on the operator's instructions under their own terms, and may
          store it outside the {JURISDICTION} jurisdiction. Where they do, transfers rely on the
          safeguards in those providers' own data-processing terms.
        </P>
      </>
    ),
  },
  {
    id: 'legal-basis',
    title: 'Why this is lawful',
    body: (
      <>
        <P>
          Where UK or EU data-protection law applies, the basis for processing is{' '}
          <Term>legitimate interests</Term>: operating a defensive security tool, showing you the
          results of the analyses you asked for, and protecting the service from abuse through rate
          limiting. That interest is balanced against the fact that the service asks for no personal
          data, sets no cookies, and does no tracking or profiling.
        </P>
        <P>
          Where an indicator you submit happens to contain personal data, you are the one who chose
          to submit it — which is why clause 2 asks you not to.
        </P>
      </>
    ),
  },
  {
    id: 'rights',
    title: 'Your rights',
    body: (
      <>
        <P>
          Under UK and EU data protection law you have the right to ask for access to your personal
          data, its correction or erasure, restriction of or objection to its processing, and its
          portability. You also have the right to complain to a supervisory authority —{' '}
          {SUPERVISORY_AUTHORITY} for the UK.
        </P>
        <Callout>
          <Term>A practical limit, stated honestly.</Term> Because there are no accounts, the service
          cannot identify you and cannot verify that a workspace is yours. In practice the fastest
          route is self-service: delete the reports yourself (clause 8). If that is not possible —
          you lost the key, or the data is in someone else's workspace — write to {CONTACT_EMAIL}{' '}
          quoting the <Mono>SC-</Mono> references concerned, and they can be removed. Without a
          reference or a key there may be no way to locate the records, and the law does not require
          the collection of extra identifying information purely to satisfy a request.
        </Callout>
      </>
    ),
  },
  {
    id: 'security',
    title: 'Security',
    body: (
      <>
        <P>
          The safety measures around hostile input are described on the front page and in the project
          documentation: samples are never executed, submitted URLs are never fetched, submitted IP
          addresses are never contacted, uploads are never web-reachable, and text extracted from
          samples is stripped of control characters before it is ever displayed or logged. Every
          database query goes through an ORM, so a submitted indicator cannot be interpreted as SQL.
        </P>
        <Callout tone="warning">
          <Term>This deployment has no authentication by default.</Term> Anything reachable is
          readable and submittable by anyone who can reach it. That is a deliberate property of a
          demonstration instance, and the reason clause 2 asks you not to submit anything
          confidential. No system is perfectly secure, and no guarantee of absolute security is
          offered.
        </Callout>
      </>
    ),
  },
  {
    id: 'children',
    title: 'Children',
    body: (
      <P>
        This is a technical tool for security practitioners. It is not directed at children, and no
        information is knowingly collected from them.
      </P>
    ),
  },
  {
    id: 'changes',
    title: 'Changes and contact',
    body: (
      <>
        <P>
          This policy may change as the software does. The date at the top of the page records the
          last material change; continuing to use the service after a change means the current
          version applies.
        </P>
        <P>
          Questions, requests and complaints about this policy go to{' '}
          <a className="text-accent hover:underline" href={`mailto:${CONTACT_EMAIL}`}>
            {CONTACT_EMAIL}
          </a>
          .
        </P>
      </>
    ),
  },
];

export default function Privacy() {
  return (
    <LegalPage
      title="Privacy policy"
      intro="What this service does with what you give it, written against the code rather than from a template."
      summary={
        <Bullets>
          <Bullet>No accounts, no cookies, no analytics, no trackers, no advertising.</Bullet>
          <Bullet>
            What you submit is stored — the indicator, the findings and the technical details —
            until you delete it.
          </Bullet>
          <Bullet>
            Uploaded files are deleted after analysis, but text extracted from them is kept in the
            report. Do not upload anything confidential.
          </Bullet>
          <Bullet>
            Your browser holds a random key so you see your own history. It identifies a browser, not
            a person.
          </Bullet>
          <Bullet>
            Your IP address is used in memory for rate limiting and is never written to the database.
          </Bullet>
        </Bullets>
      }
      clauses={CLAUSES}
    />
  );
}
