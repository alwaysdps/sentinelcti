/**
 * Submission forms for each indicator type.
 *
 * Both variants share one flow: validate locally for the obvious mistakes,
 * submit, show progress, then hand off to the report. Client-side checks exist
 * to save the user a round-trip -- the backend re-validates everything, because
 * a browser check is a convenience, never a security control.
 */

import { useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, InlineNotice, Spinner } from './ui';
import { useAction } from '../hooks/useAsync';
import { api } from '../services/api';
import { formatBytes } from '../lib/format';
import type { Analysis } from '../types/analysis';

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

function SubmitError({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-verdict-critical/35 bg-verdict-critical/10 px-4 py-3 text-sm text-verdict-critical"
    >
      {message}
    </div>
  );
}

function ProgressPanel({ steps }: { steps: string[] }) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface-2 px-4 py-4" role="status">
      <div className="flex items-center gap-2.5 text-sm text-content-primary">
        <Spinner className="h-4 w-4 text-accent" />
        Analysing indicator…
      </div>
      <ul className="mt-3 space-y-1.5 text-xs text-content-muted">
        {steps.map((step) => (
          <li key={step} className="flex items-center gap-2">
            <span className="h-1 w-1 rounded-full bg-content-muted" aria-hidden />
            {step}
          </li>
        ))}
      </ul>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Text indicators (URL, hash, IP, domain)                                    */
/* -------------------------------------------------------------------------- */

interface TextFormProps {
  title: string;
  description: string;
  label: string;
  placeholder: string;
  examples: string[];
  steps: string[];
  helper: ReactNode;
  validate: (value: string) => string | null;
  submit: (value: string) => Promise<Analysis>;
}

export function TextIndicatorForm({
  title,
  description,
  label,
  placeholder,
  examples,
  steps,
  helper,
  validate,
  submit,
}: TextFormProps) {
  const [value, setValue] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const navigate = useNavigate();
  const action = useAction(submit);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = value.trim();
    const problem = validate(trimmed);
    setLocalError(problem);
    if (problem) return;

    const result = await action.run(trimmed);
    if (result) navigate(`/analysis/${result.reference}`);
  }

  const message = localError ?? action.error?.message ?? null;

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card title={title} description={description}>
          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            <div>
              <label htmlFor="indicator" className="label-text mb-2 block">
                {label}
              </label>
              <input
                id="indicator"
                type="text"
                value={value}
                autoComplete="off"
                spellCheck={false}
                placeholder={placeholder}
                onChange={(event) => {
                  setValue(event.target.value);
                  if (localError) setLocalError(null);
                }}
                className="input-field font-mono"
                aria-invalid={Boolean(message)}
                aria-describedby={message ? 'indicator-error' : undefined}
              />
            </div>

            {message && (
              <div id="indicator-error">
                <SubmitError message={message} />
              </div>
            )}

            {action.loading ? (
              <ProgressPanel steps={steps} />
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <button type="submit" className="btn-primary" disabled={!value.trim()}>
                  Run analysis
                </button>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => {
                    setValue('');
                    setLocalError(null);
                    action.reset();
                  }}
                >
                  Clear
                </button>
              </div>
            )}
          </form>
        </Card>
      </div>

      <div className="space-y-5">
        <Card title="Examples">
          <p className="mb-3 text-xs text-content-muted">
            Reserved, non-routable values safe to submit. Click to fill the form.
          </p>
          <ul className="space-y-2">
            {examples.map((example) => (
              <li key={example}>
                <button
                  type="button"
                  onClick={() => {
                    setValue(example);
                    setLocalError(null);
                  }}
                  className="mono w-full rounded-lg border border-border-subtle bg-surface-2 px-3 py-2 text-left text-content-secondary transition-colors hover:border-accent hover:text-content-primary"
                >
                  {example}
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="What this checks">{helper}</Card>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* File upload                                                                */
/* -------------------------------------------------------------------------- */

export function FileUploadForm() {
  const [file, setFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const action = useAction((selected: File) => api.analyzeFile(selected));

  function accept(selected: File | undefined) {
    if (!selected) return;
    if (selected.size > MAX_UPLOAD_BYTES) {
      setLocalError(
        `${selected.name} is ${formatBytes(selected.size)}, which exceeds the ${formatBytes(MAX_UPLOAD_BYTES)} limit.`,
      );
      setFile(null);
      return;
    }
    setLocalError(null);
    setFile(selected);
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    const result = await action.run(file);
    if (result) navigate(`/analysis/${result.reference}`);
  }

  const message = localError ?? action.error?.message ?? null;

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card
          title="File analysis"
          description="Static analysis only. The file is hashed, identified by content and scanned for suspicious strings — never executed."
        >
          <form onSubmit={handleSubmit} className="space-y-4">
            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                accept(event.dataTransfer.files?.[0]);
              }}
              className={`rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
                dragging ? 'border-accent bg-accent/5' : 'border-border-strong bg-surface-2/40'
              }`}
            >
              <input
                ref={inputRef}
                id="file-input"
                type="file"
                className="sr-only"
                onChange={(event) => accept(event.target.files?.[0])}
              />

              <svg
                viewBox="0 0 24 24"
                className="mx-auto h-9 w-9 text-content-muted"
                fill="none"
                aria-hidden
              >
                <path
                  d="M12 16V4m0 0L8 8m4-4 4 4M4 17v1a3 3 0 0 0 3 3h10a3 3 0 0 0 3-3v-1"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>

              <p className="mt-3 text-sm text-content-secondary">
                Drag a file here, or{' '}
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="font-medium text-accent hover:underline"
                >
                  browse
                </button>
              </p>
              <p className="mt-1 text-xs text-content-muted">
                Maximum {formatBytes(MAX_UPLOAD_BYTES)}. Any file type.
              </p>
            </div>

            {file && (
              <div className="flex items-center justify-between gap-4 rounded-lg border border-border-subtle bg-surface-2 px-4 py-3">
                <div className="min-w-0">
                  <p className="mono truncate text-content-primary">{file.name}</p>
                  <p className="mt-0.5 text-xs text-content-muted">
                    {formatBytes(file.size)}
                    {file.type ? ` · declared as ${file.type}` : ' · no declared type'}
                  </p>
                </div>
                <button
                  type="button"
                  className="btn-ghost px-2 py-1 text-xs"
                  onClick={() => {
                    setFile(null);
                    if (inputRef.current) inputRef.current.value = '';
                  }}
                >
                  Remove
                </button>
              </div>
            )}

            {message && <SubmitError message={message} />}

            {action.loading ? (
              <ProgressPanel
                steps={[
                  'Streaming upload into quarantine storage',
                  'Computing MD5, SHA-1 and SHA-256 digests',
                  'Identifying file type from magic bytes',
                  'Extracting strings and matching patterns',
                  'Scoring findings and discarding the sample',
                ]}
              />
            ) : (
              <button type="submit" className="btn-primary" disabled={!file}>
                Run analysis
              </button>
            )}
          </form>
        </Card>
      </div>

      <div className="space-y-5">
        <Card title="How the file is handled">
          <ol className="space-y-3 text-xs leading-relaxed text-content-secondary">
            {[
              'Streamed to a quarantine directory outside the web root, under a random name. The original filename is kept as metadata only.',
              'Hashed in a single pass (MD5, SHA-1, SHA-256).',
              'Type identified from magic bytes — not from the extension or the declared Content-Type, both of which the submitter controls.',
              'Printable strings extracted and matched against suspicious command, encoding and network patterns.',
              'Bytes deleted. Only hashes, metadata and findings are retained.',
            ].map((step, index) => (
              <li key={step} className="flex gap-3">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border-strong text-[10px] font-semibold text-content-muted">
                  {index + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </Card>

        <InlineNotice tone="warning">
          Do not upload files containing personal or confidential data. This is a demonstration
          platform, not an accredited malware analysis service.
        </InlineNotice>
      </div>
    </div>
  );
}
