/**
 * Small async-state primitives.
 *
 * A data-fetching library would be overkill for eight endpoints and would hide
 * exactly the request lifecycle a reviewer of this project should be able to
 * read. These two hooks cover both patterns the app needs: data fetched on
 * mount, and an action the user triggers.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from '../services/api';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: ApiError | null;
}

function toApiError(error: unknown): ApiError {
  return error instanceof ApiError
    ? error
    : new ApiError('Something went wrong. Please try again.', 'unknown_error', 0);
}

/** Runs `fn` on mount and whenever `deps` change. */
export function useFetch<T>(
  fn: () => Promise<T>,
  deps: unknown[] = [],
): AsyncState<T> & {
  refresh: () => void;
} {
  const [state, setState] = useState<AsyncState<T>>({ data: null, loading: true, error: null });
  const [nonce, setNonce] = useState(0);

  // Keeps the latest callback without making it a dependency, so callers can
  // pass an inline arrow function without causing a refetch loop.
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    // Guards against a late response from a superseded request overwriting the
    // state of the current one.
    let active = true;
    setState((previous) => ({ ...previous, loading: true, error: null }));

    fnRef
      .current()
      .then((data) => active && setState({ data, loading: false, error: null }))
      .catch((error: unknown) => {
        if (active) setState({ data: null, loading: false, error: toApiError(error) });
      });

    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, refresh };
}

/** Wraps a user-triggered action (submit, delete) with loading/error state. */
export function useAction<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
) {
  const [state, setState] = useState<AsyncState<TResult>>({
    data: null,
    loading: false,
    error: null,
  });

  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async (...args: TArgs): Promise<TResult | null> => {
    setState({ data: null, loading: true, error: null });
    try {
      const data = await fnRef.current(...args);
      setState({ data, loading: false, error: null });
      return data;
    } catch (error: unknown) {
      setState({ data: null, loading: false, error: toApiError(error) });
      return null;
    }
  }, []);

  const reset = useCallback(() => setState({ data: null, loading: false, error: null }), []);

  return { ...state, run, reset };
}
