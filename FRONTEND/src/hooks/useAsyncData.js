import { useEffect, useState, useRef } from "react";

/**
 * Runs one or more async fetchers on mount, tracking loading/error state
 * consistently across pages. `fetchFn` should return a value (or an object
 * of named values) to be exposed as `data`.
 *
 * Usage:
 *   const { data, loading, error } = useAsyncData(() => getEvents());
 *   const { data, loading, error } = useAsyncData(async () => {
 *     const [events, threats] = await Promise.all([getEvents(), getThreats()]);
 *     return { events, threats };
 *   });
 */
export function useAsyncData(fetchFn, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const fetchRef = useRef(fetchFn);
  fetchRef.current = fetchFn;

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchRef.current();
        if (!cancelled) setData(result);
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load data");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, loading, error };
}
