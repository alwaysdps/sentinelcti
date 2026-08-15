/**
 * The four facts the policies cannot be written without.
 *
 * They are collected here, rather than spelled out inline across two long
 * documents, because they are the parts only the operator can decide — and a
 * policy naming the wrong jurisdiction or an unmonitored mailbox is worse than
 * one that is merely terse. Change these four values and both documents follow.
 *
 * ┌ REVIEW BEFORE PUBLISHING ────────────────────────────────────────────────┐
 * │ OPERATOR    Who is legally responsible for the deployed instance.        │
 * │ CONTACT     A mailbox that is actually read. Data-protection law needs a │
 * │             working contact point, so a wrong address is a real defect.  │
 * │ JURISDICTION Where disputes are heard and whose data-protection law      │
 * │             applies. Assumed to be the UK from the project's spelling    │
 * │             and hosting; change it if that is wrong.                     │
 * │ LAST_UPDATED Bump whenever either document changes materially.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export const OPERATOR = 'SentinelCTI';

export const CONTACT_EMAIL = 'quantaforgetech@gmail.com';

/** Governing law for the terms, and the regime the privacy rights derive from. */
export const JURISDICTION = 'England and Wales';

/** The supervisory authority a data-protection complaint would go to. */
export const SUPERVISORY_AUTHORITY = "the UK Information Commissioner's Office (ICO)";

export const LAST_UPDATED = '15 August 2026';
