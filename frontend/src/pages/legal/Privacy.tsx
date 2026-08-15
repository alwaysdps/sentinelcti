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
 *   - the retention window runs from when an analysis was created, not from
 *     last activity (clause 8), so a long session loses its earliest rows
 *     while the visitor is still working.
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
                  A random value your browser generates for the visit, stored against the record so
                  the service can show you your own history. See clause 7.
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
          report after the file itself is gone. They go when the report does — see clause 8.
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
        <P>
          The analytics described in clause 6 also see your address as part of the request. It is used
          to derive a country and a device type and is <Term>not retained against you</Term>: the
          result is a count, not a visitor record, and nothing links a page view back to an address or
          to anything you submitted.
        </P>
      </>
    ),
  },
  {
    id: 'browser-storage',
    title: 'Browser storage, analytics, and why there is no cookie banner',
    body: (
      <>
        <P>
          The site sets <Term>no cookies at all</Term>. It runs no advertising, no tag manager, no
          session recording, and nothing that follows you to other websites.
        </P>
        <P>
          It does measure <Term>aggregate traffic</Term> — how many people visited, which pages they
          opened, roughly where in the world they came from, what kind of device they used, and which
          site referred them. This is how the operator knows whether anything is being used or broken.
        </P>
        <Callout>
          <Term>The analytics are cookieless, and nothing is stored on your device for them.</Term>{' '}
          They count visits rather than following visitors: no identifier is written to your browser,
          no profile is built, and nothing is shared with an advertising network. Measurements are
          collected from this site's own domain rather than a third-party tracking host.
        </Callout>
        <P>
          That is the reason you are not shown a consent banner. UK and EU rules on cookies apply to
          storing information on, or reading it from, your device — and analytics that store nothing
          there do not engage them. Should that ever change, so would this, and you would be asked
          before anything was set.
        </P>
        <P>Two values are kept in your browser's own storage, neither of them for analytics:</P>
        <FactTable
          rows={[
            {
              id: 'workspace-storage',
              label: <Mono>sentinelcti.workspace</Mono>,
              value: (
                <>
                  Session storage, discarded when the tab closes. 256 bits of randomness generated by
                  your browser at the start of the visit, sent with each request as a header so the
                  service can show you your own analyses and not anyone else's. It identifies a
                  browsing session, not a person, and is never placed in a URL.
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
          Neither is a cookie, neither is sent to any third party, neither is used to measure
          traffic, and neither survives the end of the browsing session.
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
          who created a workspace — only that your browser holds the key. Four consequences follow,
          and all four are deliberate trade-offs for having no login:
        </P>
        <Bullets>
          <Bullet>Anyone who obtains the key can see that workspace.</Bullet>
          <Bullet>
            A workspace belongs to a browsing session, not a person. The same person on a phone and
            a laptop has two, and they cannot be merged.
          </Bullet>
          <Bullet>
            Session storage is per tab, so opening the site in a second tab starts a second, separate
            workspace. Reloading or navigating within a tab keeps the same one.
          </Bullet>
          <Bullet>
            If your browser blocks storage, no key is sent. The service still works; your submissions
            simply are not linked to you and cannot be listed later.
          </Bullet>
        </Bullets>
        <Callout>
          <Term>Nothing is shared between visitors.</Term> An earlier version of this service showed
          every visitor a set of synthetic demo analyses, so a first-time dashboard was not empty.
          It no longer does: a visitor cannot tell a deliberately shared record from someone else's
          history, and that ambiguity is worse than an empty first screen. You now see what you
          submitted in this session, and nothing else.
        </Callout>
      </>
    ),
  },
  {
    id: 'retention',
    title: 'How long it is kept',
    body: (
      <>
        <P>
          Your history lasts for the visit that created it. It is{' '}
          <Term>deleted when you leave</Term>, and reopening the site later starts you with an empty
          history rather than the last one.
        </P>
        <P>Three mechanisms, in the order they normally apply:</P>
        <Bullets>
          <Bullet>
            <Term>Uploaded file bytes go immediately.</Term> Deleted as soon as analysis finishes,
            every time, whether or not the analysis succeeded.
          </Bullet>
          <Bullet>
            <Term>The session ends.</Term> When the tab closes, the browser asks the service to
            delete the analyses belonging to that session, and the key itself is discarded with the
            tab.
          </Bullet>
          <Bullet>
            <Term>A retention sweep catches the rest.</Term> An unload request is best-effort — a
            crashed tab or a dropped connection never sends it — so the service independently
            deletes analyses older than its retention window (24 hours by default) regardless of
            whether anything asked it to.
          </Bullet>
        </Bullets>
        <P>
          You can also erase everything immediately at any point during a visit:{' '}
          <Term>Settings → Your data → “Clear my history now”</Term> deletes every analysis in the
          session, or open a single report and use “Delete report” to remove just that one.
        </P>
        <Callout>
          <Term>The retention window is measured from when an analysis was created</Term>, not from
          when you last used the service. A session left open longer than the window will lose its
          earliest analyses while you are still working. Measuring from last activity would mean
          tracking your activity, which is more information about you, not less.
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
              id: 'analytics',
              label: 'Analytics provider',
              value: (
                <>
                  Receives a record of the page view — page, referrer, coarse location, device type —
                  to produce aggregate traffic counts. It never receives the indicators you submit or
                  the contents of any report. See clause 6.
                </>
              ),
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
          results of the analyses you asked for, protecting the service from abuse through rate
          limiting, and understanding in aggregate whether the service is being used and working.
          That interest is balanced against the fact that the service asks for no personal data, sets
          no cookies, builds no profile, and does not track anyone across sites.
        </P>
        <P>
          Aggregate measurement is the mildest form this could take. It is counted rather than
          recorded per visitor, which is what makes legitimate interests the appropriate basis rather
          than consent — and it is why enabling it did not add a banner.
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
          cannot identify you and cannot verify that a workspace is yours. In practice these rights
          are mostly satisfied before you would need to invoke them: the data is deleted when you
          leave, and you can erase it yourself at any time (clause 8). If something still needs
          removing, write to {CONTACT_EMAIL} quoting the <Mono>SC-</Mono> references concerned.
          Without a reference or a key there may be no way to locate the records — and the law does
          not require the collection of extra identifying information purely to satisfy a request.
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
          <Bullet>
            No accounts, no cookies, no advertising, and nothing that follows you to other sites.
            Visits are counted in aggregate, without storing anything on your device — which is why
            there is no consent banner.
          </Bullet>
          <Bullet>
            <Term>Nothing is shared between visitors.</Term> You see what you submitted in this
            session, and nothing else — a first visit shows an empty history.
          </Bullet>
          <Bullet>
            <Term>Your history is deleted when you leave</Term>, and anything missed by that is
            removed by a retention sweep within 24 hours. Come back later and you start empty.
          </Bullet>
          <Bullet>
            Uploaded files are deleted right after analysis, but text extracted from them is kept in
            the report for as long as the report lives. Do not upload anything confidential.
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
