/**
 * Terms of service.
 *
 * The clause that matters most here is 4: this tool produces a heuristic score
 * that is explicitly not calibrated, and a Clean verdict means "no indicators
 * were detected", not "safe". Every other clause is ordinary; that one exists
 * because someone could otherwise make a real security decision on the strength
 * of a number this project has never claimed is reliable.
 */

import LegalPage, {
  Bullet,
  Bullets,
  Callout,
  Mono,
  P,
  Term,
  type Clause,
} from './LegalPage';
import { CONTACT_EMAIL, JURISDICTION, OPERATOR } from './legalMeta';

const CLAUSES: Clause[] = [
  {
    id: 'agreement',
    title: 'These terms',
    body: (
      <>
        <P>
          These terms govern your use of the SentinelCTI web application and API operated by{' '}
          {OPERATOR} (“the service”, “we”, “us”). By using the service you accept them. If you do not
          accept them, do not use it.
        </P>
        <P>
          The service is free to use, requires no account, and is offered as a demonstration and
          portfolio project rather than as a commercial product. That shapes everything below,
          particularly clauses 4, 7 and 10.
        </P>
      </>
    ),
  },
  {
    id: 'what-it-is',
    title: 'What the service does',
    body: (
      <>
        <P>
          You submit an indicator — a URL, domain, IP address, file hash or file — and the service
          returns a report: a risk score, a verdict, and the named findings that produced them.
          Analysis is strictly static. Files are not executed, submitted URLs are not fetched, and
          submitted IP addresses are not contacted.
        </P>
        <P>
          The service does not detonate malware, does not perform behavioural analysis, and is not a
          sandbox, an antivirus product, or an accredited malware analysis service. Its threat
          intelligence dataset is small, and its heuristics are documented rather than proprietary.
        </P>
      </>
    ),
  },
  {
    id: 'eligibility',
    title: 'Who may use it',
    body: (
      <P>
        You must be old enough to enter a binding agreement in your jurisdiction, and you must use
        the service in a professional or educational security context. It is a technical tool and is
        not directed at children.
      </P>
    ),
  },
  {
    id: 'no-reliance',
    title: 'The results are not a guarantee — read this one',
    body: (
      <>
        <Callout tone="warning">
          <Term>Do not make a security decision on the strength of a verdict alone.</Term> The risk
          score is a reproducible weighted sum of documented heuristics. It is not calibrated against
          a labelled corpus and carries no claim of statistical accuracy.
        </Callout>
        <P>Specifically, and by design:</P>
        <Bullets>
          <Bullet>
            <Term>A “Clean” verdict means no indicators were detected.</Term> It is not evidence of
            safety. Static analysis reveals little about a packed, encrypted or heavily obfuscated
            sample, and archive contents are never inspected at all.
          </Bullet>
          <Bullet>
            <Term>Heuristics produce false positives.</Term> A legitimate content-delivery hostname
            can look like a generated domain; a legitimate short link is still a short link.
          </Bullet>
          <Bullet>
            <Term>A MITRE ATT&CK association is a reference, not an observation.</Term> It indicates
            a technique was <em className="not-italic text-content-primary">mentioned</em> in the
            material analysed, never that it executed.
          </Bullet>
          <Bullet>
            <Term>Reports can be truncated.</Term> Pattern matching stops after a bounded window, and
            a sample that exhausts the time budget yields a partial report. This is always stated in
            the report rather than hidden — but it means absence of a finding is not proof of
            absence.
          </Bullet>
        </Bullets>
        <P>
          Treat the output as one input to triage prioritisation, alongside your own judgement and
          other tooling. It is not professional advice.
        </P>
      </>
    ),
  },
  {
    id: 'acceptable-use',
    title: 'Acceptable use',
    body: (
      <>
        <P>You agree not to:</P>
        <Bullets>
          <Bullet>
            submit confidential, personal, or legally regulated data — including personal data about
            others, health or payment data, or anything you are not entitled to disclose;
          </Bullet>
          <Bullet>
            submit any material you do not have the right to submit, or whose submission would breach
            an obligation you owe to somebody else;
          </Bullet>
          <Bullet>
            use the service, or anything it returns, to attack, probe, harass or gain unauthorised
            access to any system or person;
          </Bullet>
          <Bullet>
            attempt to circumvent the rate limit, the access gate, or any other control; to disrupt
            or overload the service; or to access another user's workspace;
          </Bullet>
          <Bullet>
            probe the service for vulnerabilities without permission, other than as described in
            clause 12;
          </Bullet>
          <Bullet>
            scrape or bulk-query the service beyond the published rate limit, or resell access to it;
          </Bullet>
          <Bullet>
            present its output as an accredited, certified or authoritative assessment, or otherwise
            misrepresent what it is.
          </Bullet>
        </Bullets>
        <P>
          Uploading live malware samples is within the intended purpose of the service, but doing so
          may breach your own organisation's policy or your local law. That judgement is yours to
          make.
        </P>
        <P>
          We may block access, remove submissions, or withdraw the service from anyone, at any time
          and without notice, where we consider it necessary.
        </P>
      </>
    ),
  },
  {
    id: 'your-submissions',
    title: 'What you submit',
    body: (
      <>
        <P>
          You keep whatever rights you already hold in what you submit. By submitting it you confirm
          you are entitled to do so, and you permit us to process, analyse and store it as described
          in the{' '}
          <a className="text-accent hover:underline" href="/privacy">
            privacy policy
          </a>
          .
        </P>
        <P>
          Uploaded file bytes are deleted after analysis. Text extracted from them is retained in the
          report — see clause 4 of the privacy policy, which is the part most people do not expect.
        </P>
      </>
    ),
  },
  {
    id: 'availability',
    title: 'Availability',
    body: (
      <>
        <P>
          The service is provided on an “as is” and “as available” basis, with{' '}
          <Term>no service level, no uptime commitment and no support obligation</Term>. It may be
          slow, unavailable, changed, or withdrawn entirely at any time and without notice.
        </P>
        <P>
          Stored analyses may be deleted at any time, including during maintenance or a schema
          change. <Term>Keep your own copy of anything you need.</Term> The service is not a records
          system and must not be relied on as one.
        </P>
      </>
    ),
  },
  {
    id: 'third-parties',
    title: 'Third-party services',
    body: (
      <P>
        The service runs on third-party hosting and database infrastructure, may query a DNS resolver,
        and may query external threat-intelligence providers where an operator has configured them.
        Those parties operate under their own terms, and we are not responsible for their acts or
        omissions. The privacy policy identifies which categories of provider are involved.
      </P>
    ),
  },
  {
    id: 'intellectual-property',
    title: 'Intellectual property and the open-source licence',
    body: (
      <>
        <P>
          The SentinelCTI source code is released under the MIT Licence, and that licence — not this
          clause — governs what you may do with the code. You may run, modify and redistribute it on
          those terms.
        </P>
        <P>
          These terms cover the hosted service rather than the source. Nothing in the MIT Licence
          entitles you to unlimited use of this particular deployment, and nothing here restricts the
          rights the MIT Licence grants you over the code.
        </P>
        <P>
          Third-party names that appear in analysis output — brand names in impersonation findings,
          MITRE ATT&CK technique identifiers, provider names — belong to their respective owners and
          are used for identification only.
        </P>
      </>
    ),
  },
  {
    id: 'liability',
    title: 'Limitation of liability',
    body: (
      <>
        <P>
          To the fullest extent permitted by law, the service is provided without warranties of any
          kind, express or implied, including any implied warranty of merchantability, fitness for a
          particular purpose, accuracy, or non-infringement.
        </P>
        <P>
          To the fullest extent permitted by law, we are not liable for any loss or damage arising
          from your use of the service or from any decision taken on the basis of a report it
          produced — including any loss caused by an undetected threat, a false positive, a truncated
          report, data loss, or unavailability of the service.
        </P>
        <Callout>
          Nothing in these terms limits liability for death or personal injury caused by negligence,
          for fraud or fraudulent misrepresentation, or for anything else that cannot lawfully be
          limited or excluded.
        </Callout>
      </>
    ),
  },
  {
    id: 'indemnity',
    title: 'Your responsibility',
    body: (
      <P>
        You are responsible for your use of the service, including anything you submit and any use
        you make of its output. If a claim is brought against us because you breached clause 5, you
        agree to cover the reasonable costs of dealing with it.
      </P>
    ),
  },
  {
    id: 'security-reports',
    title: 'Reporting a security issue',
    body: (
      <>
        <P>
          Security reports are welcome. Email{' '}
          <a className="text-accent hover:underline" href={`mailto:${CONTACT_EMAIL}`}>
            {CONTACT_EMAIL}
          </a>{' '}
          with enough detail to reproduce the issue, and allow a reasonable period to address it
          before disclosing it publicly.
        </P>
        <P>
          Please keep testing to your own workspace and your own submissions. Do not run
          denial-of-service tests, do not attempt to access other people's data, and do not use
          automated scanners against the hosted instance — the source is public, so you can stand up
          your own copy and test that as hard as you like.
        </P>
      </>
    ),
  },
  {
    id: 'changes',
    title: 'Changes to these terms',
    body: (
      <P>
        These terms may change as the software does. The date at the top of the page records the last
        material change, and continued use after a change means the current version applies.
      </P>
    ),
  },
  {
    id: 'governing-law',
    title: 'Governing law and contact',
    body: (
      <>
        <P>
          These terms and any dispute arising from them are governed by the laws of {JURISDICTION},
          and the courts of {JURISDICTION} have exclusive jurisdiction. If you are a consumer, this
          does not deprive you of the protection of the mandatory law of the country you live in.
        </P>
        <P>
          If any clause is found unenforceable, the rest continues to apply. Failing to enforce a
          clause is not a waiver of it.
        </P>
        <P>
          Questions go to{' '}
          <a className="text-accent hover:underline" href={`mailto:${CONTACT_EMAIL}`}>
            {CONTACT_EMAIL}
          </a>
          . The complete source, including the analysis logic behind every finding, is published
          under the MIT Licence — the reasoning in any report can be read in full rather than taken
          on trust. Report references take the form <Mono>SC-XXXXXX</Mono>; quoting one makes any
          query about a specific analysis far easier to answer.
        </P>
      </>
    ),
  },
];

export default function Terms() {
  return (
    <LegalPage
      title="Terms of service"
      intro="The terms you accept by using this instance, and the limits of what its output can be relied on to mean."
      summary={
        <Bullets>
          <Bullet>
            Free, no account, offered as a demonstration project — not a commercial product.
          </Bullet>
          <Bullet>
            The verdict is a triage aid, not a guarantee. “Clean” means nothing was detected, not
            that something is safe.
          </Bullet>
          <Bullet>
            Do not submit confidential or personal data, and do not use the service to attack
            anything.
          </Bullet>
          <Bullet>
            No uptime commitment and no warranty. Stored analyses may be deleted at any time — keep
            your own copies.
          </Bullet>
          <Bullet>The source is MIT-licensed; these terms cover this hosted instance.</Bullet>
        </Bullets>
      }
      clauses={CLAUSES}
    />
  );
}
