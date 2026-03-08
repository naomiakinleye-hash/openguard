// useSSE — subscribes to a Server-Sent Events endpoint and calls `onMessage`
// with the parsed JSON payload for each event received.
//
// The connection is re-established automatically on error after a 3-second
// back-off. Pass `null` as `url` to disable the hook (e.g. when not logged in).
import { useEffect, useRef } from 'react';

export function useSSE(url: string | null, onMessage: (data: unknown) => void): void {
  const callbackRef = useRef(onMessage);

  useEffect(() => {
    callbackRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    if (!url) return;

    let es: EventSource;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      es = new EventSource(url as string);

      es.onmessage = (evt) => {
        try {
          callbackRef.current(JSON.parse(evt.data as string));
        } catch {
          // Ignore parse errors — malformed SSE frames are dropped silently.
        }
      };

      es.onerror = () => {
        es.close();
        if (!cancelled) {
          retryTimer = setTimeout(connect, 3000);
        }
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
      es?.close();
    };
  }, [url]);
}
