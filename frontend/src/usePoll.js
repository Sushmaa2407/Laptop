import { useEffect, useRef, useState } from "react";

// Calls fn now and then every `ms` milliseconds. Returns { data, error, reload }. Pauses while the tab is hidden.
export function usePoll(fn, ms, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const [tick, setTick] = useState(0);

  // Different inputs (e.g. another filter) mean different data: drop the old data instead of showing it.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => setData(null), deps);

  useEffect(() => {
    let alive = true;
    const run = async () => {
      if (document.hidden) return;
      try {
        const result = await fnRef.current();
        if (alive) {
          setData(result);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e);
      }
    };
    run();
    const id = setInterval(run, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, tick, ...deps]);

  return { data, error, reload: () => setTick((t) => t + 1) };
}
